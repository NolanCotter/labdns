package audit

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/state"
	"time"
)

type Event struct {
	Type, Actor, Provider, RecordName, RecordType, PreviousValue, NewValue, Result, Reason, TransactionID string
	Metadata                                                                                              map[string]string
}

func Log(ctx context.Context, s *state.Store, e Event) error {
	_ = ctx
	m, _ := json.Marshal(e.Metadata)
	_, err := s.DB.Exec("INSERT INTO audit_events(id,timestamp,event_type,actor,provider,record_name,record_type,previous_value,new_value,result,reason,transaction_id,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", uuid.NewString(), time.Now().UTC().Format(time.RFC3339Nano), e.Type, e.Actor, e.Provider, e.RecordName, e.RecordType, e.PreviousValue, e.NewValue, e.Result, e.Reason, e.TransactionID, string(m))
	return err
}
