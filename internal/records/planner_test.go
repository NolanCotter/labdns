package records

import (
	"context"
	"testing"
	"time"

	"github.com/labdns/labdns/internal/dns"
)

func TestUnmanagedRecordBlocksUpdate(t *testing.T) {
	d := []dns.DesiredRecord{{ServiceID: "s", Zone: "home.arpa", Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.20", TTL: time.Minute}}
	existing := []dns.DNSRecord{{Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.15", Managed: false}}
	p, e := Plan(context.Background(), d, existing)
	if e != nil || len(p) != 1 || p[0].Type != dns.ChangeConflict {
		t.Fatalf("expected conflict: %#v %v", p, e)
	}
	if !HasBlocking(p) {
		t.Fatal("conflict should block apply")
	}
	if e := RequireAdoptable(p[0]); e != nil {
		t.Fatal(e)
	}
}
func TestManagedRecordUpdates(t *testing.T) {
	d := []dns.DesiredRecord{{ServiceID: "s", Zone: "home.arpa", Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.20", TTL: time.Minute}}
	existing := []dns.DNSRecord{{Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.15", Managed: true}}
	p, _ := Plan(context.Background(), d, existing)
	if p[0].Type != dns.ChangeUpdate || p[0].Previous == nil {
		t.Fatalf("expected update, got %s", p[0].Type)
	}
}
func TestNoChangeWhenValueMatches(t *testing.T) {
	d := []dns.DesiredRecord{{ServiceID: "s", Zone: "home.arpa", Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.20", TTL: time.Minute}}
	existing := []dns.DNSRecord{{Name: "SONARR.home.arpa.", Type: dns.RecordA, Value: "10.0.0.20", TTL: 0, Managed: false}}
	p, e := Plan(context.Background(), d, existing)
	if e != nil || len(p) != 1 || p[0].Type != dns.ChangeNoChange {
		t.Fatalf("expected no change: %#v %v", p, e)
	}
}
func TestCreateWhenAbsent(t *testing.T) {
	d := []dns.DesiredRecord{{ServiceID: "s", Zone: "home.arpa", Name: "sonarr.home.arpa", Type: dns.RecordAAAA, Value: "fd00::20", TTL: time.Minute}}
	p, e := Plan(context.Background(), d, nil)
	if e != nil || len(p) != 1 || p[0].Type != dns.ChangeCreate {
		t.Fatalf("expected create: %#v %v", p, e)
	}
	if p[0].Record.Managed != true || p[0].Record.Metadata["managed-by"] != "labdns" {
		t.Fatalf("ownership metadata missing: %#v", p[0].Record)
	}
}
func TestMultipleExistingRecordsConflict(t *testing.T) {
	d := []dns.DesiredRecord{{ServiceID: "s", Zone: "home.arpa", Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.20", TTL: time.Minute}}
	existing := []dns.DNSRecord{
		{Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.15", Managed: true},
		{Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.16", Managed: true},
	}
	p, _ := Plan(context.Background(), d, existing)
	if p[0].Type != dns.ChangeConflict {
		t.Fatalf("expected conflict, got %s", p[0].Type)
	}
}
func TestSameNameDifferentTypes(t *testing.T) {
	d := []dns.DesiredRecord{
		{ServiceID: "s", Zone: "home.arpa", Name: "app.home.arpa", Type: dns.RecordA, Value: "10.0.0.20", TTL: time.Minute},
		{ServiceID: "s", Zone: "home.arpa", Name: "app.home.arpa", Type: dns.RecordTXT, Value: "managed-by=labdns", TTL: time.Minute},
	}
	existing := []dns.DNSRecord{{Name: "app.home.arpa", Type: dns.RecordA, Value: "10.0.0.20", Managed: true}}
	p, _ := Plan(context.Background(), d, existing)
	if len(p) != 2 || p[0].Type != dns.ChangeNoChange || p[1].Type != dns.ChangeCreate {
		t.Fatalf("unexpected plan: %#v", p)
	}
}
func TestRequireAdoptableRejectsOtherChanges(t *testing.T) {
	if e := RequireAdoptable(dns.Change{Type: dns.ChangeCreate}); e == nil {
		t.Fatal("expected error")
	}
	if e := RequireAdoptable(dns.Change{Type: dns.ChangeConflict}); e == nil {
		t.Fatal("expected error for conflict without previous record")
	}
}
func TestHasBlocking(t *testing.T) {
	if HasBlocking([]dns.Change{{Type: dns.ChangeCreate}, {Type: dns.ChangeBlocked}}) != true {
		t.Fatal("blocked change should block")
	}
	if HasBlocking([]dns.Change{{Type: dns.ChangeCreate}, {Type: dns.ChangeNoChange}}) {
		t.Fatal("non-blocking plan reported blocking")
	}
}
