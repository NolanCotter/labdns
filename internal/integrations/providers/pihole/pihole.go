// Package pihole implements Pi-hole's supported HTTP custom-DNS interface.
package pihole

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/records"
	"github.com/labdns/labdns/internal/secrets"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Provider struct {
	Instance   dns.ProviderInstance
	Credential dns.SecretRef
	Client     *http.Client
}

func New(baseURL string, credential dns.SecretRef) *Provider {
	return &Provider{Instance: dns.ProviderInstance{ID: "pihole", BaseURL: strings.TrimRight(baseURL, "/")}, Credential: credential, Client: &http.Client{Timeout: 10 * time.Second}}
}
func (p *Provider) ID() string          { return "pihole" }
func (p *Provider) DisplayName() string { return "Pi-hole" }
func (p *Provider) Detect(ctx context.Context) ([]dns.ProviderInstance, error) {
	r, e := p.request(ctx, http.MethodGet, "/admin/api.php?summaryRaw", nil)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		return nil, fmt.Errorf("Pi-hole detection returned %s", r.Status)
	}
	return []dns.ProviderInstance{p.Instance}, nil
}
func (p *Provider) Validate(ctx context.Context, _ dns.ProviderInstance, credential dns.SecretRef) error {
	if credential != "" {
		p.Credential = credential
	}
	r, e := p.request(ctx, http.MethodGet, "/admin/api.php?summaryRaw", nil)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusUnauthorized || r.StatusCode == http.StatusForbidden {
		return fmt.Errorf("Pi-hole authentication failed")
	}
	if r.StatusCode >= 300 {
		return fmt.Errorf("Pi-hole validation returned %s", r.Status)
	}
	return nil
}
func (p *Provider) Capabilities(context.Context, dns.ProviderInstance) (dns.Capabilities, error) {
	return dns.Capabilities{SupportsA: true}, nil
}
func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.DNSRecord, error) {
	r, e := p.request(ctx, http.MethodGet, "/admin/api.php?customdns", nil)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		return nil, fmt.Errorf("Pi-hole list records: %s", r.Status)
	}
	var wire map[string]any
	if e = json.NewDecoder(r.Body).Decode(&wire); e != nil {
		return nil, e
	}
	entries, _ := wire["data"].([]any)
	out := []dns.DNSRecord{}
	for _, v := range entries {
		name, value := "", ""
		switch x := v.(type) {
		case map[string]any:
			name, _ = x["domain"].(string)
			value, _ = x["ip"].(string)
		case []any:
			if len(x) >= 2 {
				value, _ = x[0].(string)
				name, _ = x[1].(string)
			}
		}
		if name == "" || value == "" {
			continue
		}
		if zone != "" && !strings.HasSuffix(strings.TrimSuffix(name, "."), strings.TrimSuffix(zone, ".")) {
			continue
		}
		out = append(out, dns.DNSRecord{ID: uuid.NewString(), ProviderID: p.ID(), Zone: zone, Name: strings.TrimSuffix(name, "."), Type: dns.RecordA, Value: value, TTL: 0, Managed: false})
	}
	return out, nil
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
	switch c.Type {
	case dns.ChangeCreate:
		return p.callCustom(ctx, "add", c.Record.Name, c.Record.Value)
	case dns.ChangeDelete:
		return p.callCustom(ctx, "delete", c.Record.Name, c.Record.Value)
	case dns.ChangeUpdate:
		if c.Previous == nil {
			return fmt.Errorf("update lacks previous record")
		}
		if e := p.callCustom(ctx, "delete", c.Previous.Name, c.Previous.Value); e != nil {
			return e
		}
		return p.callCustom(ctx, "add", c.Record.Name, c.Record.Value)
	}
	return fmt.Errorf("unsupported change %s", c.Type)
}
func (p *Provider) callCustom(ctx context.Context, action, name, value string) error {
	q := url.Values{}
	q.Set("customdns", action)
	q.Set("domain", name)
	q.Set("ip", value)
	r, e := p.request(ctx, http.MethodGet, "/admin/api.php?"+q.Encode(), nil)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		return fmt.Errorf("Pi-hole %s %s: %s", action, name, r.Status)
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	if success, ok := body["success"].(bool); ok && !success {
		return fmt.Errorf("Pi-hole rejected %s for %s", action, name)
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
		status := dns.CheckFail
		evidence := "record absent"
		for _, r := range existing {
			if strings.EqualFold(r.Name, d.Name) && r.Type == d.Type && r.Value == d.Value {
				status = dns.CheckPass
				evidence = "Pi-hole provider contains expected record"
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
			if e := p.callCustom(ctx, "delete", c.Record.Name, c.Record.Value); e != nil {
				return e
			}
		case dns.ChangeDelete:
			if c.Previous != nil {
				if e := p.callCustom(ctx, "add", c.Previous.Name, c.Previous.Value); e != nil {
					return e
				}
			}
		case dns.ChangeUpdate:
			if e := p.callCustom(ctx, "delete", c.Record.Name, c.Record.Value); e != nil {
				return e
			}
			if c.Previous != nil {
				if e := p.callCustom(ctx, "add", c.Previous.Name, c.Previous.Value); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func (p *Provider) request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	req, e := http.NewRequestWithContext(ctx, method, p.Instance.BaseURL+path, nil)
	if e != nil {
		return nil, e
	}
	if p.Credential != "" {
		token, e := secrets.Resolve(p.Credential)
		if e != nil {
			return nil, e
		}
		req.Header.Set("X-Auth", token)
	}
	return p.Client.Do(req)
}
