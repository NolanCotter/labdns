// Package rfc2136 implements DNS dynamic updates (RFC 2136) with optional TSIG.
package rfc2136

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/records"
	"github.com/labdns/labdns/internal/secrets"
	mdns "github.com/miekg/dns"
)

type Provider struct {
	Instance   dns.ProviderInstance
	Server     string
	Zone       string
	KeyName    string
	Algorithm  string
	SecretRef  dns.SecretRef
	Timeout    time.Duration
	ExchangeFn func(*mdns.Msg, string) (*mdns.Msg, error)
	TransferFn func(*mdns.Msg, string) (chan *mdns.Envelope, error)
}

func New(server, zone, keyName, algorithm string, secret dns.SecretRef) *Provider {
	if algorithm == "" {
		algorithm = mdns.HmacSHA256
	}
	return &Provider{Instance: dns.ProviderInstance{ID: "rfc2136", BaseURL: server}, Server: server, Zone: strings.TrimSuffix(zone, "."), KeyName: keyName, Algorithm: algorithm, SecretRef: secret, Timeout: 10 * time.Second}
}
func (p *Provider) ID() string          { return "rfc2136" }
func (p *Provider) DisplayName() string { return "RFC 2136 dynamic DNS" }
func (p *Provider) Detect(ctx context.Context) ([]dns.ProviderInstance, error) {
	if e := p.probe(ctx); e != nil {
		return nil, e
	}
	return []dns.ProviderInstance{p.Instance}, nil
}
func (p *Provider) Validate(ctx context.Context, _ dns.ProviderInstance, credential dns.SecretRef) error {
	if credential != "" {
		p.SecretRef = credential
	}
	return p.probe(ctx)
}
func (p *Provider) probe(ctx context.Context) error {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(p.Zone), mdns.TypeSOA)
	r, e := p.exchange(ctx, m)
	if e != nil {
		return e
	}
	if r.Rcode != mdns.RcodeSuccess && r.Rcode != mdns.RcodeNameError {
		return fmt.Errorf("RFC2136 server returned %s", mdns.RcodeToString[r.Rcode])
	}
	return nil
}
func (p *Provider) Capabilities(context.Context, dns.ProviderInstance) (dns.Capabilities, error) {
	return dns.Capabilities{SupportsA: true, SupportsAAAA: true, SupportsCNAME: true, SupportsPTR: true, SupportsSRV: true, SupportsTXT: true, SupportsZones: true, SupportsAtomicEdit: true}, nil
}
func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.DNSRecord, error) {
	z := strings.TrimSuffix(zone, ".")
	if z == "" {
		z = p.Zone
	}
	if z == "" {
		return nil, fmt.Errorf("RFC2136 zone is required")
	}
	m := new(mdns.Msg)
	m.SetAxfr(mdns.Fqdn(z))
	envs, e := p.transfer(ctx, m)
	if e != nil {
		return nil, e
	}
	out := []dns.DNSRecord{}
	for env := range envs {
		if env.Error != nil {
			return nil, env.Error
		}
		for _, rr := range env.RR {
			if r, ok := fromRR(rr, z); ok {
				out = append(out, r)
			}
		}
	}
	return out, nil
}
func fromRR(rr mdns.RR, zone string) (dns.DNSRecord, bool) {
	h := rr.Header()
	r := dns.DNSRecord{ID: uuid.NewString(), ProviderID: "rfc2136", Zone: zone, Name: strings.TrimSuffix(strings.ToLower(h.Name), "."), TTL: time.Duration(h.Ttl) * time.Second, Managed: false}
	switch v := rr.(type) {
	case *mdns.A:
		r.Type, r.Value = dns.RecordA, v.A.String()
	case *mdns.AAAA:
		r.Type, r.Value = dns.RecordAAAA, v.AAAA.String()
	case *mdns.CNAME:
		r.Type, r.Value = dns.RecordCNAME, strings.TrimSuffix(v.Target, ".")
	case *mdns.PTR:
		r.Type, r.Value = dns.RecordPTR, strings.TrimSuffix(v.Ptr, ".")
	case *mdns.SRV:
		r.Type, r.Value = dns.RecordSRV, fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, strings.TrimSuffix(v.Target, "."))
	case *mdns.TXT:
		r.Type, r.Value = dns.RecordTXT, strings.Join(v.Txt, " ")
	default:
		return dns.DNSRecord{}, false
	}
	return r, true
}
func toRR(r dns.DNSRecord) (mdns.RR, error) {
	h := mdns.RR_Header{Name: mdns.Fqdn(r.Name), Rrtype: typeCode(r.Type), Class: mdns.ClassINET, Ttl: uint32(r.TTL.Seconds())}
	if h.Ttl == 0 {
		h.Ttl = 300
	}
	switch r.Type {
	case dns.RecordA:
		ip, e := netip.ParseAddr(r.Value)
		if e != nil || !ip.Is4() {
			return nil, fmt.Errorf("invalid A value %q", r.Value)
		}
		return &mdns.A{Hdr: h, A: net.IP(ip.AsSlice())}, nil
	case dns.RecordAAAA:
		ip, e := netip.ParseAddr(r.Value)
		if e != nil || !ip.Is6() {
			return nil, fmt.Errorf("invalid AAAA value %q", r.Value)
		}
		return &mdns.AAAA{Hdr: h, AAAA: net.IP(ip.AsSlice())}, nil
	case dns.RecordCNAME:
		return &mdns.CNAME{Hdr: h, Target: mdns.Fqdn(r.Value)}, nil
	case dns.RecordPTR:
		return &mdns.PTR{Hdr: h, Ptr: mdns.Fqdn(r.Value)}, nil
	case dns.RecordSRV:
		f := strings.Fields(r.Value)
		if len(f) != 4 {
			return nil, fmt.Errorf("invalid SRV value %q; want priority weight port target", r.Value)
		}
		pri, e1 := strconv.Atoi(f[0])
		weight, e2 := strconv.Atoi(f[1])
		port, e3 := strconv.Atoi(f[2])
		if e1 != nil || e2 != nil || e3 != nil {
			return nil, fmt.Errorf("invalid SRV value %q", r.Value)
		}
		return &mdns.SRV{Hdr: h, Priority: uint16(pri), Weight: uint16(weight), Port: uint16(port), Target: mdns.Fqdn(f[3])}, nil
	case dns.RecordTXT:
		return &mdns.TXT{Hdr: h, Txt: []string{r.Value}}, nil
	}
	return nil, fmt.Errorf("unsupported record type %s", r.Type)
}
func typeCode(t dns.RecordType) uint16 {
	switch t {
	case dns.RecordAAAA:
		return mdns.TypeAAAA
	case dns.RecordCNAME:
		return mdns.TypeCNAME
	case dns.RecordPTR:
		return mdns.TypePTR
	case dns.RecordSRV:
		return mdns.TypeSRV
	case dns.RecordTXT:
		return mdns.TypeTXT
	default:
		return mdns.TypeA
	}
}
func (p *Provider) Plan(ctx context.Context, d []dns.DesiredRecord, e []dns.DNSRecord) ([]dns.Change, error) {
	return records.Plan(ctx, d, e)
}
func (p *Provider) Apply(ctx context.Context, changes []dns.Change) ([]dns.AppliedChange, error) {
	applied := []dns.AppliedChange{}
	for _, c := range changes {
		if c.Type == dns.ChangeNoChange {
			continue
		}
		if c.Type == dns.ChangeConflict || c.Type == dns.ChangeBlocked {
			return applied, fmt.Errorf("cannot apply blocked plan: %s", c.Reason)
		}
		if e := p.mutate(ctx, c); e != nil {
			return applied, e
		}
		applied = append(applied, dns.AppliedChange{Change: c, AppliedAt: time.Now().UTC()})
	}
	return applied, nil
}
func (p *Provider) mutate(ctx context.Context, c dns.Change) error {
	zone := c.Record.Zone
	if zone == "" {
		zone = p.Zone
	}
	m := new(mdns.Msg)
	m.SetUpdate(mdns.Fqdn(zone))
	switch c.Type {
	case dns.ChangeCreate:
		rr, e := toRR(c.Record)
		if e != nil {
			return e
		}
		m.Insert([]mdns.RR{rr})
	case dns.ChangeDelete:
		rr, e := toRR(c.Record)
		if e != nil {
			return e
		}
		m.Remove([]mdns.RR{rr})
	case dns.ChangeUpdate:
		if c.Previous == nil {
			return fmt.Errorf("update lacks previous record")
		}
		old, e := toRR(*c.Previous)
		if e != nil {
			return e
		}
		fresh, e := toRR(c.Record)
		if e != nil {
			return e
		}
		m.Remove([]mdns.RR{old})
		m.Insert([]mdns.RR{fresh})
	default:
		return fmt.Errorf("unsupported change %s", c.Type)
	}
	r, e := p.exchange(ctx, m)
	if e != nil {
		return e
	}
	if r.Rcode != mdns.RcodeSuccess {
		return fmt.Errorf("RFC2136 update for %s returned %s", c.Record.Name, mdns.RcodeToString[r.Rcode])
	}
	return nil
}
func (p *Provider) Verify(ctx context.Context, desired []dns.DesiredRecord) ([]dns.CheckResult, error) {
	existing, e := p.ListRecords(ctx, p.Zone)
	if e != nil {
		return nil, e
	}
	out := make([]dns.CheckResult, 0, len(desired))
	for _, d := range desired {
		status, evidence := dns.CheckFail, "record absent"
		for _, r := range existing {
			if strings.EqualFold(r.Name, d.Name) && r.Type == d.Type && r.Value == d.Value {
				status, evidence = dns.CheckPass, "RFC2136 zone contains expected record"
				break
			}
		}
		out = append(out, dns.CheckResult{ID: uuid.NewString(), Name: d.Name, Target: d.Value, Status: status, Severity: dns.SeverityCritical, Evidence: evidence})
	}
	return out, nil
}
func (p *Provider) Rollback(ctx context.Context, changes []dns.AppliedChange) error {
	for i := len(changes) - 1; i >= 0; i-- {
		c := changes[i].Change
		var e error
		switch c.Type {
		case dns.ChangeCreate:
			e = p.mutate(ctx, dns.Change{Type: dns.ChangeDelete, Record: c.Record})
		case dns.ChangeDelete:
			if c.Previous != nil {
				e = p.mutate(ctx, dns.Change{Type: dns.ChangeCreate, Record: *c.Previous})
			}
		case dns.ChangeUpdate:
			if c.Previous != nil {
				e = p.mutate(ctx, dns.Change{Type: dns.ChangeUpdate, Record: *c.Previous, Previous: &c.Record})
			}
		}
		if e != nil {
			return e
		}
	}
	return nil
}
func (p *Provider) exchange(ctx context.Context, m *mdns.Msg) (*mdns.Msg, error) {
	if p.ExchangeFn != nil {
		return p.ExchangeFn(m, p.Server)
	}
	if e := p.sign(m); e != nil {
		return nil, e
	}
	c := &mdns.Client{Timeout: p.Timeout}
	if p.KeyName != "" {
		s, e := secrets.Resolve(p.SecretRef)
		if e != nil {
			return nil, e
		}
		c.TsigSecret = map[string]string{p.KeyName: s}
	}
	r, _, e := c.ExchangeContext(ctx, m, p.Server)
	return r, e
}
func (p *Provider) transfer(ctx context.Context, m *mdns.Msg) (chan *mdns.Envelope, error) {
	if p.TransferFn != nil {
		return p.TransferFn(m, p.Server)
	}
	if e := p.sign(m); e != nil {
		return nil, e
	}
	t := &mdns.Transfer{}
	if p.KeyName != "" {
		s, e := secrets.Resolve(p.SecretRef)
		if e != nil {
			return nil, e
		}
		t.TsigSecret = map[string]string{p.KeyName: s}
	}
	ch, e := t.In(m, p.Server)
	if e != nil {
		return nil, e
	}
	out := make(chan *mdns.Envelope)
	go func() {
		defer close(out)
		for env := range ch {
			select {
			case out <- env:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
func (p *Provider) sign(m *mdns.Msg) error {
	if p.KeyName == "" {
		return nil
	}
	m.SetTsig(p.KeyName, p.Algorithm, 300, time.Now().Unix())
	return nil
}
