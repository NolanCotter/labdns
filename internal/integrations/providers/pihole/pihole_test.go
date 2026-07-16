package pihole

import (
	"context"
	"github.com/labdns/labdns/internal/dns"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListAndApply(t *testing.T) {
	var calls []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.RawQuery)
		if r.URL.Query().Get("customdns") == "" {
			_, _ = w.Write([]byte(`{"data":[["10.0.0.20","jellyfin.home.arpa"]]}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer s.Close()
	p := New(s.URL, "")
	records, e := p.ListRecords(context.Background(), "home.arpa")
	if e != nil || len(records) != 1 || records[0].Value != "10.0.0.20" {
		t.Fatalf("records=%#v err=%v", records, e)
	}
	_, e = p.Apply(context.Background(), []dns.Change{{Type: dns.ChangeCreate, Record: dns.DNSRecord{Name: "sonarr.home.arpa", Value: "10.0.0.20", Type: dns.RecordA, TTL: time.Minute}}})
	if e != nil || len(calls) < 2 {
		t.Fatalf("apply failed: %v %#v", e, calls)
	}
}
