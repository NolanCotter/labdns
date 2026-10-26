package verification

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/labdns/labdns/internal/dns"
	mdns "github.com/miekg/dns"
)

func dnsServer(t *testing.T, handler mdns.HandlerFunc) string {
	t.Helper()
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDirectPassAndFail(t *testing.T) {
	addr := dnsServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Name == "app.home.arpa." && q.Qtype == mdns.TypeA {
			m.Answer = append(m.Answer, &mdns.A{Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.5")})
		}
		_ = w.WriteMsg(m)
	})
	desired := []dns.DesiredRecord{
		{Name: "app.home.arpa", Type: dns.RecordA, Value: "10.0.0.5"},
		{Name: "missing.home.arpa", Type: dns.RecordA, Value: "10.0.0.6"},
	}
	got := Direct(context.Background(), addr, desired, time.Second)
	if len(got) != 2 || got[0].Status != dns.CheckPass || got[1].Status != dns.CheckFail {
		t.Fatalf("results=%#v", got)
	}
	if got[0].Duration <= 0 {
		t.Fatal("duration not recorded")
	}
}

func TestDirectWithoutServerWarns(t *testing.T) {
	got := Direct(context.Background(), "", []dns.DesiredRecord{{Name: "a", Type: dns.RecordA, Value: "10.0.0.1"}}, time.Second)
	if len(got) != 1 || got[0].Status != dns.CheckWarn || got[0].Severity != dns.SeverityWarning {
		t.Fatalf("results=%#v", got)
	}
}

func TestDirectHandlesQueryErrors(t *testing.T) {
	got := Direct(context.Background(), "127.0.0.1:1", []dns.DesiredRecord{{Name: "a", Type: dns.RecordA, Value: "10.0.0.1"}}, 50*time.Millisecond)
	if len(got) != 1 || got[0].Status != dns.CheckFail {
		t.Fatalf("results=%#v", got)
	}
}

func TestTypeCode(t *testing.T) {
	cases := map[dns.RecordType]uint16{
		dns.RecordA:     mdns.TypeA,
		dns.RecordAAAA:  mdns.TypeAAAA,
		dns.RecordCNAME: mdns.TypeCNAME,
		dns.RecordPTR:   mdns.TypePTR,
		dns.RecordSRV:   mdns.TypeSRV,
		dns.RecordTXT:   mdns.TypeTXT,
	}
	for typ, want := range cases {
		if got := typeCode(typ); got != want {
			t.Fatalf("typeCode(%s) = %d, want %d", typ, got, want)
		}
	}
}

func TestProbe(t *testing.T) {
	addr := dnsServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	if e := Probe(context.Background(), addr, time.Second); e != nil {
		t.Fatal(e)
	}
	if e := Probe(context.Background(), "", time.Second); e == nil {
		t.Fatal("expected error for empty server")
	}
	if e := Probe(context.Background(), "127.0.0.1:1", 50*time.Millisecond); e == nil {
		t.Fatal("expected error for unreachable server")
	}
}
