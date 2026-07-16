// Package records produces safe plans. A content match never implies ownership.
package records

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/dns"
)

func Plan(_ context.Context, desired []dns.DesiredRecord, existing []dns.DNSRecord) ([]dns.Change, error) {
	byKey := map[string][]dns.DNSRecord{}
	for _, r := range existing {
		byKey[key(r.Name, r.Type)] = append(byKey[key(r.Name, r.Type)], r)
	}
	changes := make([]dns.Change, 0, len(desired))
	for _, d := range desired {
		matches := byKey[key(d.Name, d.Type)]
		record := dns.DNSRecord{ID: uuid.NewString(), Zone: d.Zone, Name: canonical(d.Name), Type: d.Type, Value: d.Value, TTL: d.TTL, Managed: true, SourceID: d.ServiceID, Metadata: map[string]string{"managed-by": "labdns", "labdns-service-id": d.ServiceID}}
		if len(matches) == 0 {
			changes = append(changes, dns.Change{ID: uuid.NewString(), Type: dns.ChangeCreate, Record: record, Reason: "record does not exist"})
			continue
		}
		if len(matches) > 1 {
			changes = append(changes, dns.Change{ID: uuid.NewString(), Type: dns.ChangeConflict, Record: record, Reason: "multiple existing records for this name and type"})
			continue
		}
		old := matches[0]
		if old.Value == d.Value && (old.TTL == 0 || old.TTL == d.TTL) {
			changes = append(changes, dns.Change{ID: uuid.NewString(), Type: dns.ChangeNoChange, Record: record, Previous: &old, Reason: "managed record is current"})
			continue
		}
		if !old.Managed {
			changes = append(changes, dns.Change{ID: uuid.NewString(), Type: dns.ChangeConflict, Record: record, Previous: &old, Reason: "existing record is unmanaged; explicit adoption required"})
			continue
		}
		changes = append(changes, dns.Change{ID: uuid.NewString(), Type: dns.ChangeUpdate, Record: record, Previous: &old, Reason: "managed record differs"})
	}
	return changes, nil
}
func HasBlocking(changes []dns.Change) bool {
	for _, c := range changes {
		if c.Type == dns.ChangeConflict || c.Type == dns.ChangeBlocked {
			return true
		}
	}
	return false
}
func key(name string, t dns.RecordType) string { return canonical(name) + "|" + string(t) }
func canonical(s string) string                { return strings.TrimSuffix(strings.ToLower(s), ".") }
func RequireAdoptable(c dns.Change) error {
	if c.Type != dns.ChangeConflict || c.Previous == nil {
		return fmt.Errorf("change is not an adoptable conflict")
	}
	return nil
}
