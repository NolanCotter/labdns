package transaction

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/state"
)

type Result struct {
	ID           string              `json:"id"`
	Applied      []dns.AppliedChange `json:"applied"`
	Verification []dns.CheckResult   `json:"verification"`
	RolledBack   bool                `json:"rolled_back"`
}

func Apply(ctx context.Context, s *state.Store, p dns.Provider, changes []dns.Change, desired []dns.DesiredRecord, verify func(context.Context, []dns.DesiredRecord) []dns.CheckResult) (Result, error) {
	r := Result{ID: uuid.NewString()}
	if e := s.BeginTransaction(r.ID); e != nil {
		return r, e
	}
	applied, e := p.Apply(ctx, changes)
	r.Applied = applied
	if e == nil {
		r.Verification = verify(ctx, desired)
		for _, c := range r.Verification {
			if c.Status == dns.CheckFail {
				e = fmt.Errorf("mandatory verification failed for %s: %s", c.Name, c.Evidence)
				break
			}
		}
	}
	if e == nil {
		_ = s.FinishTransaction(r.ID, "committed", nil)
		return r, nil
	}
	rollbackErr := p.Rollback(ctx, applied)
	r.RolledBack = rollbackErr == nil
	if rollbackErr == nil {
		_ = s.FinishTransaction(r.ID, "rolled_back", e)
		return r, fmt.Errorf("apply failed and rollback succeeded: %w", e)
	}
	_ = s.FinishTransaction(r.ID, "rollback_incomplete", fmt.Errorf("%w; rollback: %v", e, rollbackErr))
	return r, fmt.Errorf("apply failed and rollback incomplete: %w", e)
}
