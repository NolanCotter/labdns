package state_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/labdns/labdns/internal/audit"
	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/state"
)

func open(t *testing.T) *state.Store {
	t.Helper()
	s, e := state.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestManagedRecordLifecycle(t *testing.T) {
	s := open(t)
	if e := s.MarkManaged("pihole", "home.arpa", "app.home.arpa", "A", "10.0.0.2", "svc"); e != nil {
		t.Fatal(e)
	}
	ok, e := s.IsManaged("pihole", "home.arpa", "app.home.arpa", "A")
	if e != nil || !ok {
		t.Fatalf("managed=%v err=%v", ok, e)
	}
	if e = s.ReconcileManaged("pihole", []dns.DesiredRecord{{Zone: "home.arpa", Name: "app.home.arpa", Type: dns.RecordA, Value: "10.0.0.3", ServiceID: "svc"}}, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	list, e := s.ListManaged("pihole")
	if e != nil || len(list) != 1 || list[0].Value != "10.0.0.3" || list[0].StaleSince != nil {
		t.Fatalf("list=%#v err=%v", list, e)
	}
	now := time.Now().UTC()
	if e = s.ReconcileManaged("pihole", nil, now); e != nil {
		t.Fatal(e)
	}
	list, _ = s.ListManaged("pihole")
	if len(list) != 1 || list[0].StaleSince == nil {
		t.Fatalf("record not marked stale: %#v", list)
	}
	stale, e := s.StaleRecords("pihole", now.Add(time.Second))
	if e != nil || len(stale) != 1 || !stale[0].Managed {
		t.Fatalf("stale=%#v err=%v", stale, e)
	}
	if stale, _ = s.StaleRecords("pihole", now.Add(-time.Minute)); len(stale) != 0 {
		t.Fatalf("unexpected early stale records: %#v", stale)
	}
	if e = s.ReconcileManaged("pihole", []dns.DesiredRecord{{Zone: "home.arpa", Name: "app.home.arpa", Type: dns.RecordA, Value: "10.0.0.3", ServiceID: "svc"}}, now); e != nil {
		t.Fatal(e)
	}
	list, _ = s.ListManaged("pihole")
	if list[0].StaleSince != nil {
		t.Fatal("stale flag not cleared")
	}
	if e = s.RemoveManaged("pihole", "home.arpa", "app.home.arpa", "A"); e != nil {
		t.Fatal(e)
	}
	if ok, _ = s.IsManaged("pihole", "home.arpa", "app.home.arpa", "A"); ok {
		t.Fatal("record still managed")
	}
}

func TestTransactionsAndAudit(t *testing.T) {
	s := open(t)
	if e := s.BeginTransaction("tx1"); e != nil {
		t.Fatal(e)
	}
	if e := s.FinishTransaction("tx1", "committed", nil); e != nil {
		t.Fatal(e)
	}
	if e := audit.Log(context.Background(), s, audit.Event{Type: "record_create", Actor: "test", Provider: "pihole", RecordName: "a.home.arpa", RecordType: "A", NewValue: "10.0.0.1", Result: "success", TransactionID: "tx1", Metadata: map[string]string{"k": "v"}}); e != nil {
		t.Fatal(e)
	}
	txns, e := s.ListTransactions()
	if e != nil || len(txns) != 1 || txns[0].Status != "committed" {
		t.Fatalf("txns=%#v err=%v", txns, e)
	}
	events, e := s.ListAudit()
	if e != nil || len(events) != 1 || events[0].NewValue != "10.0.0.1" {
		t.Fatalf("events=%#v err=%v", events, e)
	}
}

func TestInterruptStaleTransactions(t *testing.T) {
	s := open(t)
	if e := s.BeginTransaction("old"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("UPDATE transactions SET started_at=? WHERE id=?", time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339Nano), "old"); e != nil {
		t.Fatal(e)
	}
	if e := s.BeginTransaction("new"); e != nil {
		t.Fatal(e)
	}
	n, e := s.InterruptStaleTransactions(time.Now().UTC().Add(-time.Hour))
	if e != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, e)
	}
	txns, _ := s.ListTransactions()
	for _, tx := range txns {
		if tx.ID == "old" && tx.Status != "interrupted" {
			t.Fatalf("old transaction status = %s", tx.Status)
		}
		if tx.ID == "new" && tx.Status != "running" {
			t.Fatalf("new transaction status = %s", tx.Status)
		}
	}
}

func TestIntegrityCheck(t *testing.T) {
	s := open(t)
	if e := s.IntegrityCheck(); e != nil {
		t.Fatal(e)
	}
}

func TestBackupRefusesOverwrite(t *testing.T) {
	s := open(t)
	if e := s.MarkManaged("pihole", "home.arpa", "a.home.arpa", "A", "10.0.0.1", "svc"); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.db")
	if e := s.Backup(path); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal(e)
	}
	if e := s.Backup(path); e == nil {
		t.Fatal("expected overwrite refusal")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	restoreDir := filepath.Join(dir, "restore")
	if e = os.MkdirAll(restoreDir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(restoreDir, "labdns.db"), b, 0600); e != nil {
		t.Fatal(e)
	}
	restored, e := state.Open(restoreDir)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	if e = restored.IntegrityCheck(); e != nil {
		t.Fatal(e)
	}
	list, e := restored.ListManaged("pihole")
	if e != nil || len(list) != 1 || list[0].Value != "10.0.0.1" {
		t.Fatalf("backup contents lost: %#v err=%v", list, e)
	}
}

func TestExport(t *testing.T) {
	s := open(t)
	if e := s.MarkManaged("pihole", "home.arpa", "a.home.arpa", "A", "10.0.0.1", "svc"); e != nil {
		t.Fatal(e)
	}
	out, e := s.Export()
	if e != nil || out.Version != 1 || len(out.Managed) != 1 || out.Managed[0].Name != "a.home.arpa" {
		t.Fatalf("export=%#v err=%v", out, e)
	}
}
