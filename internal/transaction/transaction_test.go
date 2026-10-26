package transaction

import (
	"context"
	"errors"
	"testing"

	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/state"
)

type fakeProvider struct {
	applied      []dns.AppliedChange
	applyErr     error
	rollbackErr  error
	rollbackRuns int
}

func (f *fakeProvider) ID() string          { return "fake" }
func (f *fakeProvider) DisplayName() string { return "Fake" }
func (f *fakeProvider) Detect(context.Context) ([]dns.ProviderInstance, error) {
	return []dns.ProviderInstance{{ID: "fake"}}, nil
}
func (f *fakeProvider) Validate(context.Context, dns.ProviderInstance, dns.SecretRef) error {
	return nil
}
func (f *fakeProvider) Capabilities(context.Context, dns.ProviderInstance) (dns.Capabilities, error) {
	return dns.Capabilities{SupportsA: true}, nil
}
func (f *fakeProvider) ListRecords(context.Context, string) ([]dns.DNSRecord, error) {
	return nil, nil
}
func (f *fakeProvider) Plan(context.Context, []dns.DesiredRecord, []dns.DNSRecord) ([]dns.Change, error) {
	return nil, nil
}
func (f *fakeProvider) Apply(_ context.Context, changes []dns.Change) ([]dns.AppliedChange, error) {
	if f.applyErr != nil {
		return f.applied, f.applyErr
	}
	for _, c := range changes {
		f.applied = append(f.applied, dns.AppliedChange{Change: c})
	}
	return f.applied, nil
}
func (f *fakeProvider) Verify(context.Context, []dns.DesiredRecord) ([]dns.CheckResult, error) {
	return nil, nil
}
func (f *fakeProvider) Rollback(context.Context, []dns.AppliedChange) error {
	f.rollbackRuns++
	return f.rollbackErr
}

func openStore(t *testing.T) *state.Store {
	t.Helper()
	s, e := state.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestApplyCommits(t *testing.T) {
	s := openStore(t)
	p := &fakeProvider{}
	changes := []dns.Change{{Type: dns.ChangeCreate, Record: dns.DNSRecord{Name: "a.home.arpa", Type: dns.RecordA, Value: "10.0.0.1"}}}
	res, e := Apply(context.Background(), s, p, changes, nil, func(context.Context, []dns.DesiredRecord) []dns.CheckResult {
		return []dns.CheckResult{{Name: "a.home.arpa", Status: dns.CheckPass}}
	})
	if e != nil || res.RolledBack || len(res.Applied) != 1 {
		t.Fatalf("res=%#v err=%v", res, e)
	}
	txns, _ := s.ListTransactions()
	if len(txns) != 1 || txns[0].Status != "committed" {
		t.Fatalf("txns=%#v", txns)
	}
}
func TestVerificationFailureRollsBack(t *testing.T) {
	s := openStore(t)
	p := &fakeProvider{}
	changes := []dns.Change{{Type: dns.ChangeCreate, Record: dns.DNSRecord{Name: "a.home.arpa", Type: dns.RecordA, Value: "10.0.0.1"}}}
	res, e := Apply(context.Background(), s, p, changes, nil, func(context.Context, []dns.DesiredRecord) []dns.CheckResult {
		return []dns.CheckResult{{Name: "a.home.arpa", Status: dns.CheckFail, Evidence: "missing"}}
	})
	if e == nil || !res.RolledBack || p.rollbackRuns != 1 {
		t.Fatalf("res=%#v err=%v rollbacks=%d", res, e, p.rollbackRuns)
	}
	txns, _ := s.ListTransactions()
	if len(txns) != 1 || txns[0].Status != "rolled_back" {
		t.Fatalf("txns=%#v", txns)
	}
}
func TestApplyFailureRollsBack(t *testing.T) {
	s := openStore(t)
	p := &fakeProvider{applyErr: errors.New("provider down")}
	_, e := Apply(context.Background(), s, p, []dns.Change{{Type: dns.ChangeCreate}}, nil, func(context.Context, []dns.DesiredRecord) []dns.CheckResult { return nil })
	if e == nil || p.rollbackRuns != 1 {
		t.Fatalf("err=%v rollbacks=%d", e, p.rollbackRuns)
	}
}
func TestRollbackFailureIsReported(t *testing.T) {
	s := openStore(t)
	p := &fakeProvider{applyErr: errors.New("provider down"), rollbackErr: errors.New("rollback down")}
	_, e := Apply(context.Background(), s, p, []dns.Change{{Type: dns.ChangeCreate}}, nil, func(context.Context, []dns.DesiredRecord) []dns.CheckResult { return nil })
	if e == nil || p.rollbackRuns != 1 {
		t.Fatalf("err=%v rollbacks=%d", e, p.rollbackRuns)
	}
	txns, _ := s.ListTransactions()
	if len(txns) != 1 || txns[0].Status != "rollback_incomplete" {
		t.Fatalf("txns=%#v", txns)
	}
}
