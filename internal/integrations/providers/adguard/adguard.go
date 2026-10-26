// Package adguard implements AdGuard Home's rewrite HTTP API.
package adguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/records"
	"github.com/labdns/labdns/internal/secrets"
)

type Provider struct {
	Instance   dns.ProviderInstance
	Username   string
	Credential dns.SecretRef
	Client     *http.Client
}

type rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

func New(baseURL, username string, credential dns.SecretRef) *Provider {
	return &Provider{Instance: dns.ProviderInstance{ID: "adguard", BaseURL: strings.TrimRight(baseURL, "/")}, Username: username, Credential: credential, Client: &http.Client{Timeout: 10 * time.Second}}
}
func (p *Provider) ID() string          { return "adguard" }
func (p *Provider) DisplayName() string { return "AdGuard Home" }
func (p *Provider) Detect(ctx context.Context) ([]dns.ProviderInstance, error) {
	if e := p.check(ctx); e != nil {
		return nil, e
	}
	return []dns.ProviderInstance{p.Instance}, nil
}
func (p *Provider) Validate(ctx context.Context, _ dns.ProviderInstance, credential dns.SecretRef) error {
	if credential != "" {
		p.Credential = credential
	}
	return p.check(ctx)
}
func (p *Provider) check(ctx context.Context) error {
	r, e := p.request(ctx, http.MethodGet, "/control/status", nil)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusUnauthorized || r.StatusCode == http.StatusForbidden {
		return fmt.Errorf("AdGuard Home authentication failed")
	}
	if r.StatusCode >= 300 {
		return fmt.Errorf("AdGuard Home status returned %s", r.Status)
	}
	return nil
}
func (p *Provider) Capabilities(context.Context, dns.ProviderInstance) (dns.Capabilities, error) {
	return dns.Capabilities{SupportsA: true, SupportsAAAA: true, SupportsCNAME: true}, nil
}
func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.DNSRecord, error) {
	r, e := p.request(ctx, http.MethodGet, "/control/rewrite/list", nil)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		return nil, fmt.Errorf("AdGuard Home list rewrites: %s", r.Status)
	}
	var items []rewrite
	if e = json.NewDecoder(r.Body).Decode(&items); e != nil {
		return nil, e
	}
	out := []dns.DNSRecord{}
	for _, item := range items {
		name := strings.TrimSuffix(strings.ToLower(item.Domain), ".")
		if name == "" || item.Answer == "" {
			continue
		}
		if zone != "" && !strings.HasSuffix(name, "."+strings.TrimSuffix(strings.ToLower(zone), ".")) && name != strings.TrimSuffix(strings.ToLower(zone), ".") {
			continue
		}
		out = append(out, dns.DNSRecord{ID: uuid.NewString(), ProviderID: p.ID(), Zone: zone, Name: name, Type: recordType(item.Answer), Value: item.Answer, TTL: 0, Managed: false})
	}
	return out, nil
}
func recordType(answer string) dns.RecordType {
	if ip, e := netip.ParseAddr(answer); e == nil {
		if ip.Is4() {
			return dns.RecordA
		}
		return dns.RecordAAAA
	}
	return dns.RecordCNAME
}
func (p *Provider) Plan(ctx context.Context, d []dns.DesiredRecord, e []dns.DNSRecord) ([]dns.Change, error) {
	for _, r := range d {
		if !supported(r.Type) {
			return nil, fmt.Errorf("AdGuard Home does not support %s records", r.Type)
		}
	}
	return records.Plan(ctx, d, e)
}
func supported(t dns.RecordType) bool {
	return t == dns.RecordA || t == dns.RecordAAAA || t == dns.RecordCNAME
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
	switch c.Type {
	case dns.ChangeCreate:
		return p.call(ctx, "/control/rewrite/add", rewrite{Domain: c.Record.Name, Answer: c.Record.Value})
	case dns.ChangeDelete:
		return p.call(ctx, "/control/rewrite/delete", rewrite{Domain: c.Record.Name, Answer: c.Record.Value})
	case dns.ChangeUpdate:
		if c.Previous == nil {
			return fmt.Errorf("update lacks previous record")
		}
		if e := p.call(ctx, "/control/rewrite/delete", rewrite{Domain: c.Previous.Name, Answer: c.Previous.Value}); e != nil {
			return e
		}
		return p.call(ctx, "/control/rewrite/add", rewrite{Domain: c.Record.Name, Answer: c.Record.Value})
	}
	return fmt.Errorf("unsupported change %s", c.Type)
}
func (p *Provider) call(ctx context.Context, path string, body rewrite) error {
	r, e := p.request(ctx, http.MethodPost, path, body)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusUnauthorized || r.StatusCode == http.StatusForbidden {
		return fmt.Errorf("AdGuard Home authentication failed")
	}
	if r.StatusCode >= 300 {
		return fmt.Errorf("AdGuard Home %s: %s", path, r.Status)
	}
	return nil
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
				status, evidence = dns.CheckPass, "AdGuard Home contains expected record"
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
		switch c.Type {
		case dns.ChangeCreate:
			if e := p.call(ctx, "/control/rewrite/delete", rewrite{Domain: c.Record.Name, Answer: c.Record.Value}); e != nil {
				return e
			}
		case dns.ChangeDelete:
			if c.Previous != nil {
				if e := p.call(ctx, "/control/rewrite/add", rewrite{Domain: c.Previous.Name, Answer: c.Previous.Value}); e != nil {
					return e
				}
			}
		case dns.ChangeUpdate:
			if e := p.call(ctx, "/control/rewrite/delete", rewrite{Domain: c.Record.Name, Answer: c.Record.Value}); e != nil {
				return e
			}
			if c.Previous != nil {
				if e := p.call(ctx, "/control/rewrite/add", rewrite{Domain: c.Previous.Name, Answer: c.Previous.Value}); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func (p *Provider) request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var buf *bytes.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, e
		}
		buf = bytes.NewReader(b)
	} else {
		buf = bytes.NewReader(nil)
	}
	req, e := http.NewRequestWithContext(ctx, method, p.Instance.BaseURL+path, buf)
	if e != nil {
		return nil, e
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.Credential != "" || p.Username != "" {
		password := ""
		if p.Credential != "" {
			password, e = secrets.Resolve(p.Credential)
			if e != nil {
				return nil, e
			}
		}
		req.SetBasicAuth(p.Username, password)
	}
	return p.Client.Do(req)
}
