package state

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/labdns/labdns/internal/dns"
	_ "modernc.org/sqlite"
)

type Store struct {
	DB   *sql.DB
	Path string
}

type ManagedRecord struct {
	ProviderID string
	Zone       string
	Name       string
	Type       string
	Value      string
	ServiceID  string
	UpdatedAt  time.Time
	StaleSince *time.Time
}
type Transaction struct {
	ID          string    `json:"id"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	Status      string    `json:"status"`
	Error       string    `json:"error,omitempty"`
}
type AuditEvent struct {
	ID            string `json:"id"`
	Timestamp     string `json:"timestamp"`
	EventType     string `json:"event_type"`
	Actor         string `json:"actor"`
	Provider      string `json:"provider,omitempty"`
	RecordName    string `json:"record_name,omitempty"`
	RecordType    string `json:"record_type,omitempty"`
	PreviousValue string `json:"previous_value,omitempty"`
	NewValue      string `json:"new_value,omitempty"`
	Result        string `json:"result"`
	Reason        string `json:"reason,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	Metadata      string `json:"metadata,omitempty"`
}
type Export struct {
	Version  int             `json:"version"`
	Managed  []ManagedRecord `json:"managed_records"`
	Txns     []Transaction   `json:"transactions"`
	Audit    []AuditEvent    `json:"audit_events"`
	Exported time.Time       `json:"exported_at"`
}

func Open(dataDir string) (*Store, error) {
	if e := os.MkdirAll(dataDir, 0700); e != nil {
		return nil, e
	}
	path := filepath.Join(dataDir, "labdns.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	s := &Store{DB: db, Path: path}
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
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL, provider TEXT, record_name TEXT, record_type TEXT, previous_value TEXT, new_value TEXT, result TEXT NOT NULL, reason TEXT, transaction_id TEXT, metadata TEXT); CREATE TABLE IF NOT EXISTS transactions (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL, error TEXT); CREATE TABLE IF NOT EXISTS managed_records (provider_id TEXT NOT NULL, zone TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL, service_id TEXT NOT NULL, updated_at TEXT NOT NULL, stale_since TEXT, PRIMARY KEY(provider_id, zone, name, type));`)
	if e != nil {
		return e
	}
	if !s.hasColumn("managed_records", "stale_since") {
		if _, e = s.DB.Exec("ALTER TABLE managed_records ADD COLUMN stale_since TEXT"); e != nil {
			return e
		}
	}
	_, e = s.DB.Exec("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(?,?)", 1, time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
func (s *Store) hasColumn(table, column string) bool {
	rows, e := s.DB.Query("PRAGMA table_info(" + table + ")")
	if e != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt any
		if rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk) == nil && name == column {
			return true
		}
	}
	return false
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
	_, e := s.DB.Exec(`INSERT INTO managed_records(provider_id,zone,name,type,value,service_id,updated_at,stale_since) VALUES(?,?,?,?,?,?,?,NULL) ON CONFLICT(provider_id,zone,name,type) DO UPDATE SET value=excluded.value,service_id=excluded.service_id,updated_at=excluded.updated_at,stale_since=NULL`, provider, zone, name, typ, value, serviceID, time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
func (s *Store) RemoveManaged(provider, zone, name, typ string) error {
	_, e := s.DB.Exec("DELETE FROM managed_records WHERE provider_id=? AND zone=? AND name=? AND type=?", provider, zone, name, typ)
	return e
}
func (s *Store) IsManaged(provider, zone, name, typ string) (bool, error) {
	var n int
	e := s.DB.QueryRow("SELECT COUNT(1) FROM managed_records WHERE provider_id=? AND zone=? AND name=? AND type=?", provider, zone, name, typ).Scan(&n)
	return n > 0, e
}
func (s *Store) ListManaged(provider string) ([]ManagedRecord, error) {
	rows, e := s.DB.Query(`SELECT provider_id,zone,name,type,value,service_id,updated_at,stale_since FROM managed_records WHERE provider_id=? ORDER BY zone,name,type`, provider)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ManagedRecord{}
	for rows.Next() {
		var r ManagedRecord
		var updated string
		var stale sql.NullString
		if e = rows.Scan(&r.ProviderID, &r.Zone, &r.Name, &r.Type, &r.Value, &r.ServiceID, &updated, &stale); e != nil {
			return nil, e
		}
		r.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		if stale.Valid {
			if t, err := time.Parse(time.RFC3339Nano, stale.String); err == nil {
				r.StaleSince = &t
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReconcileManaged records positive ownership for desired records and marks
// previously managed records that disappeared from the desired set as stale.
func (s *Store) ReconcileManaged(provider string, desired []dns.DesiredRecord, now time.Time) error {
	existing, e := s.ListManaged(provider)
	if e != nil {
		return e
	}
	want := map[string]bool{}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	nowText := now.UTC().Format(time.RFC3339Nano)
	for _, d := range desired {
		k := recordKey(d.Zone, d.Name, string(d.Type))
		want[k] = true
		if _, e = tx.Exec(`INSERT INTO managed_records(provider_id,zone,name,type,value,service_id,updated_at,stale_since) VALUES(?,?,?,?,?,?,?,NULL) ON CONFLICT(provider_id,zone,name,type) DO UPDATE SET value=excluded.value,service_id=excluded.service_id,updated_at=excluded.updated_at,stale_since=NULL`, provider, d.Zone, d.Name, string(d.Type), d.Value, d.ServiceID, nowText); e != nil {
			return e
		}
	}
	for _, r := range existing {
		if want[recordKey(r.Zone, r.Name, r.Type)] || r.StaleSince != nil {
			continue
		}
		if _, e = tx.Exec("UPDATE managed_records SET stale_since=? WHERE provider_id=? AND zone=? AND name=? AND type=?", nowText, provider, r.Zone, r.Name, r.Type); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) StaleRecords(provider string, before time.Time) ([]dns.DNSRecord, error) {
	rows, e := s.DB.Query(`SELECT zone,name,type,value,service_id,stale_since FROM managed_records WHERE provider_id=? AND stale_since IS NOT NULL AND stale_since<=? ORDER BY stale_since,zone,name,type`, provider, before.UTC().Format(time.RFC3339Nano))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []dns.DNSRecord{}
	for rows.Next() {
		var zone, name, typ, value, service, stale string
		if e = rows.Scan(&zone, &name, &typ, &value, &service, &stale); e != nil {
			return nil, e
		}
		out = append(out, dns.DNSRecord{ProviderID: provider, Zone: zone, Name: name, Type: dns.RecordType(typ), Value: value, Managed: true, SourceID: service, Metadata: map[string]string{"stale_since": stale}})
	}
	return out, rows.Err()
}
func (s *Store) InterruptStaleTransactions(before time.Time) (int64, error) {
	res, e := s.DB.Exec("UPDATE transactions SET status='interrupted',completed_at=?,error='stale running transaction repaired' WHERE status='running' AND started_at<?", time.Now().UTC().Format(time.RFC3339Nano), before.UTC().Format(time.RFC3339Nano))
	if e != nil {
		return 0, e
	}
	return res.RowsAffected()
}

// Backup writes a consistent snapshot of the database without copying WAL
// sidecars into the destination.
func (s *Store) Backup(path string) error {
	if _, e := os.Stat(path); e == nil {
		return fmt.Errorf("refusing to overwrite existing backup %s", path)
	}
	if _, e := s.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	in, e := os.Open(s.Path)
	if e != nil {
		return e
	}
	defer in.Close()
	tmp := path + ".tmp"
	out, e := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	if _, e = io.Copy(out, in); e != nil {
		out.Close()
		os.Remove(tmp)
		return e
	}
	if e = out.Sync(); e != nil {
		out.Close()
		os.Remove(tmp)
		return e
	}
	if e = out.Close(); e != nil {
		os.Remove(tmp)
		return e
	}
	return os.Rename(tmp, path)
}
func (s *Store) Export() (Export, error) {
	out := Export{Version: 1, Exported: time.Now().UTC(), Managed: []ManagedRecord{}, Txns: []Transaction{}, Audit: []AuditEvent{}}
	var e error
	if out.Managed, e = s.ListManagedAll(); e != nil {
		return out, e
	}
	if out.Txns, e = s.ListTransactions(); e != nil {
		return out, e
	}
	if out.Audit, e = s.ListAudit(); e != nil {
		return out, e
	}
	return out, nil
}
func (s *Store) ListManagedAll() ([]ManagedRecord, error) {
	rows, e := s.DB.Query(`SELECT provider_id,zone,name,type,value,service_id,updated_at,stale_since FROM managed_records ORDER BY provider_id,zone,name,type`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ManagedRecord{}
	for rows.Next() {
		var r ManagedRecord
		var updated string
		var stale sql.NullString
		if e = rows.Scan(&r.ProviderID, &r.Zone, &r.Name, &r.Type, &r.Value, &r.ServiceID, &updated, &stale); e != nil {
			return nil, e
		}
		r.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		if stale.Valid {
			if t, err := time.Parse(time.RFC3339Nano, stale.String); err == nil {
				r.StaleSince = &t
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) ListTransactions() ([]Transaction, error) {
	rows, e := s.DB.Query("SELECT id,started_at,COALESCE(completed_at,''),status,COALESCE(error,'') FROM transactions ORDER BY started_at")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Transaction{}
	for rows.Next() {
		var t Transaction
		var started, completed string
		if e = rows.Scan(&t.ID, &started, &completed, &t.Status, &t.Error); e != nil {
			return nil, e
		}
		t.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		if completed != "" {
			t.CompletedAt, _ = time.Parse(time.RFC3339Nano, completed)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (s *Store) ListAudit() ([]AuditEvent, error) {
	rows, e := s.DB.Query("SELECT id,timestamp,event_type,actor,COALESCE(provider,''),COALESCE(record_name,''),COALESCE(record_type,''),COALESCE(previous_value,''),COALESCE(new_value,''),result,COALESCE(reason,''),COALESCE(transaction_id,''),COALESCE(metadata,'') FROM audit_events ORDER BY timestamp")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var a AuditEvent
		if e = rows.Scan(&a.ID, &a.Timestamp, &a.EventType, &a.Actor, &a.Provider, &a.RecordName, &a.RecordType, &a.PreviousValue, &a.NewValue, &a.Result, &a.Reason, &a.TransactionID, &a.Metadata); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func recordKey(zone, name, typ string) string { return zone + "|" + name + "|" + typ }
