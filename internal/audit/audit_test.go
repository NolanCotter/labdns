package audit_test

import (
	"context"
	"testing"

	"github.com/labdns/labdns/internal/audit"
	"github.com/labdns/labdns/internal/state"
)

func TestLogStoresMetadata(t *testing.T) {
	s, e := state.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = audit.Log(context.Background(), s, audit.Event{Type: "record_create", Actor: "test", Result: "success", Metadata: map[string]string{"zone": "home.arpa"}}); e != nil {
		t.Fatal(e)
	}
	events, e := s.ListAudit()
	if e != nil || len(events) != 1 || events[0].Metadata != `{"zone":"home.arpa"}` {
		t.Fatalf("events=%#v err=%v", events, e)
	}
}
