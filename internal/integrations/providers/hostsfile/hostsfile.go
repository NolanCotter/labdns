// Package hostsfile implements a managed block in a standard hosts file.
package hostsfile

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/records"
)

type Provider struct {
	Path string
	mu   sync.Mutex
}

type entry struct {
	Raw       string
	IP        string
	Names     []string
	Comment   string
	Managed   bool
	ServiceID string
}

func New(path string) *Provider { return &Provider{Path: path} }
func (p *Provider) ID() string  { return "hostsfile" }
func (p *Provider) DisplayName() string {
	return "Hosts file"
}
func (p *Provider) Detect(context.Context) ([]dns.ProviderInstance, error) {
	if _, e := os.Stat(p.Path); e != nil {
		return nil, fmt.Errorf("hosts file %s: %w", p.Path, e)
	}
	return []dns.ProviderInstance{{ID: p.ID(), BaseURL: p.Path}}, nil
}
func (p *Provider) Validate(context.Context, dns.ProviderInstance, dns.SecretRef) error {
	f, e := os.OpenFile(p.Path, os.O_WRONLY|os.O_APPEND, 0)
	if e != nil {
		return fmt.Errorf("hosts file %s is not writable: %w", p.Path, e)
	}
	return f.Close()
}
func (p *Provider) Capabilities(context.Context, dns.ProviderInstance) (dns.Capabilities, error) {
	return dns.Capabilities{SupportsA: true, SupportsAAAA: true}, nil
}
func (p *Provider) ListRecords(_ context.Context, zone string) ([]dns.DNSRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entries, e := p.load()
	if e != nil {
		return nil, e
	}
	out := []dns.DNSRecord{}
	z := strings.TrimSuffix(strings.ToLower(zone), ".")
	for _, en := range entries {
		if en.Raw != "" {
			continue
		}
		t := dns.RecordA
		if ip, err := netip.ParseAddr(en.IP); err == nil && ip.Is6() {
			t = dns.RecordAAAA
		}
		for _, name := range en.Names {
			n := strings.TrimSuffix(strings.ToLower(name), ".")
			if z != "" && n != z && !strings.HasSuffix(n, "."+z) {
				continue
			}
			out = append(out, dns.DNSRecord{ID: uuid.NewString(), ProviderID: p.ID(), Zone: zone, Name: n, Type: t, Value: en.IP, TTL: 0, Managed: en.Managed, SourceID: en.ServiceID})
		}
	}
	return out, nil
}
func (p *Provider) Plan(ctx context.Context, d []dns.DesiredRecord, e []dns.DNSRecord) ([]dns.Change, error) {
	for _, r := range d {
		if r.Type != dns.RecordA && r.Type != dns.RecordAAAA {
			return nil, fmt.Errorf("hosts file does not support %s records", r.Type)
		}
	}
	return records.Plan(ctx, d, e)
}
func (p *Provider) Apply(ctx context.Context, changes []dns.Change) ([]dns.AppliedChange, error) {
	_ = ctx
	p.mu.Lock()
	defer p.mu.Unlock()
	entries, e := p.load()
	if e != nil {
		return nil, e
	}
	applied := []dns.AppliedChange{}
	for _, c := range changes {
		if c.Type == dns.ChangeNoChange {
			continue
		}
		if c.Type == dns.ChangeConflict || c.Type == dns.ChangeBlocked {
			return applied, fmt.Errorf("cannot apply blocked plan: %s", c.Reason)
		}
		next, e := mutate(entries, c)
		if e != nil {
			return applied, e
		}
		entries = next
		applied = append(applied, dns.AppliedChange{Change: c, AppliedAt: time.Now().UTC()})
	}
	if e = p.save(entries); e != nil {
		return applied, e
	}
	return applied, nil
}
func mutate(entries []entry, c dns.Change) ([]entry, error) {
	switch c.Type {
	case dns.ChangeCreate:
		return upsert(entries, c.Record), nil
	case dns.ChangeDelete:
		return removeEntry(entries, c.Record.Name, c.Record.Value), nil
	case dns.ChangeUpdate:
		if c.Previous == nil {
			return nil, fmt.Errorf("update lacks previous record")
		}
		entries = removeEntry(entries, c.Previous.Name, c.Previous.Value)
		return upsert(entries, c.Record), nil
	}
	return nil, fmt.Errorf("unsupported change %s", c.Type)
}
func upsert(entries []entry, r dns.DNSRecord) []entry {
	entries = removeEntry(entries, r.Name, r.Value)
	comment := "labdns:managed " + r.SourceID
	if r.SourceID == "" {
		comment = "labdns:managed"
	}
	return append(entries, entry{IP: r.Value, Names: []string{strings.TrimSuffix(strings.ToLower(r.Name), ".")}, Comment: comment, Managed: true, ServiceID: r.SourceID})
}
func removeEntry(entries []entry, name, value string) []entry {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	out := entries[:0]
	for _, en := range entries {
		if en.Raw == "" && en.IP == value && containsName(en.Names, name) {
			continue
		}
		out = append(out, en)
	}
	return out
}
func containsName(names []string, name string) bool {
	for _, n := range names {
		if strings.TrimSuffix(strings.ToLower(n), ".") == name {
			return true
		}
	}
	return false
}
func (p *Provider) Verify(ctx context.Context, desired []dns.DesiredRecord) ([]dns.CheckResult, error) {
	existing, e := p.ListRecords(ctx, "")
	if e != nil {
		return nil, e
	}
	out := make([]dns.CheckResult, 0, len(desired))
	for _, d := range desired {
		status, evidence := dns.CheckFail, "record absent"
		for _, r := range existing {
			if strings.EqualFold(r.Name, d.Name) && r.Type == d.Type && r.Value == d.Value {
				status, evidence = dns.CheckPass, "hosts file contains expected record"
				break
			}
		}
		out = append(out, dns.CheckResult{ID: uuid.NewString(), Name: d.Name, Target: d.Value, Status: status, Severity: dns.SeverityCritical, Evidence: evidence})
	}
	return out, nil
}
func (p *Provider) Rollback(ctx context.Context, changes []dns.AppliedChange) error {
	inverse := make([]dns.Change, 0, len(changes))
	for i := len(changes) - 1; i >= 0; i-- {
		c := changes[i].Change
		switch c.Type {
		case dns.ChangeCreate:
			inverse = append(inverse, dns.Change{Type: dns.ChangeDelete, Record: c.Record})
		case dns.ChangeDelete:
			if c.Previous != nil {
				inverse = append(inverse, dns.Change{Type: dns.ChangeCreate, Record: *c.Previous})
			}
		case dns.ChangeUpdate:
			if c.Previous != nil {
				inverse = append(inverse, dns.Change{Type: dns.ChangeUpdate, Record: *c.Previous, Previous: &c.Record})
			}
		}
	}
	_, e := p.Apply(ctx, inverse)
	return e
}
func (p *Provider) load() ([]entry, error) {
	b, e := os.ReadFile(p.Path)
	if e != nil {
		return nil, e
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	out := make([]entry, 0, len(lines))
	for _, raw := range lines {
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			out = append(out, entry{Raw: raw})
			continue
		}
		data, comment, _ := strings.Cut(t, "#")
		fields := strings.Fields(data)
		if len(fields) < 2 {
			out = append(out, entry{Raw: raw})
			continue
		}
		en := entry{IP: fields[0], Names: fields[1:], Comment: strings.TrimSpace(comment)}
		if strings.Contains(en.Comment, "labdns:managed") {
			en.Managed = true
			en.ServiceID = strings.TrimSpace(strings.TrimPrefix(en.Comment, "labdns:managed"))
		}
		out = append(out, en)
	}
	return out, nil
}
func (p *Provider) save(entries []entry) error {
	var b strings.Builder
	for i, en := range entries {
		if en.Raw != "" {
			b.WriteString(en.Raw)
		} else {
			b.WriteString(en.IP)
			b.WriteString(" ")
			b.WriteString(strings.Join(en.Names, " "))
			if en.Comment != "" {
				b.WriteString(" # ")
				b.WriteString(en.Comment)
			}
		}
		if i < len(entries)-1 {
			b.WriteString("\n")
		}
	}
	if len(entries) > 0 {
		b.WriteString("\n")
	}
	if e := os.MkdirAll(filepath.Dir(p.Path), 0700); e != nil {
		return e
	}
	mode := os.FileMode(0644)
	if st, e := os.Stat(p.Path); e == nil {
		mode = st.Mode().Perm()
	}
	tmp := p.Path + ".labdns.tmp"
	if e := os.WriteFile(tmp, []byte(b.String()), mode); e != nil {
		return e
	}
	return os.Rename(tmp, p.Path)
}
func (p *Provider) Entries() ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entries, e := p.load()
	if e != nil {
		return nil, e
	}
	out := make([]string, 0, len(entries))
	for _, en := range entries {
		if en.Raw != "" {
			continue
		}
		out = append(out, en.IP+" "+strings.Join(en.Names, " "))
	}
	sort.Strings(out)
	return out, nil
}
