package records

import (
	"context"
	"github.com/labdns/labdns/internal/dns"
	"testing"
	"time"
)

func TestUnmanagedRecordBlocksUpdate(t *testing.T) {
	d := []dns.DesiredRecord{{ServiceID: "s", Zone: "home.arpa", Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.20", TTL: time.Minute}}
	existing := []dns.DNSRecord{{Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.15", Managed: false}}
	p, e := Plan(context.Background(), d, existing)
	if e != nil || len(p) != 1 || p[0].Type != dns.ChangeConflict {
		t.Fatalf("expected conflict: %#v %v", p, e)
	}
}
func TestManagedRecordUpdates(t *testing.T) {
	d := []dns.DesiredRecord{{ServiceID: "s", Zone: "home.arpa", Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.20", TTL: time.Minute}}
	existing := []dns.DNSRecord{{Name: "sonarr.home.arpa", Type: dns.RecordA, Value: "10.0.0.15", Managed: true}}
	p, _ := Plan(context.Background(), d, existing)
	if p[0].Type != dns.ChangeUpdate {
		t.Fatalf("expected update, got %s", p[0].Type)
	}
}
