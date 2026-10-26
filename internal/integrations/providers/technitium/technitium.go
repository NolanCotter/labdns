// Package technitium implements the Technitium DNS Server HTTP API.
package technitium

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/records"
	"github.com/labdns/labdns/internal/secrets"
)

type Provider struct {
	Instance   dns.ProviderInstance
	Zone       string
	Credential dns.SecretRef
	Client     *http.Client
}

type apiResponse struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage"`
	Response     struct {
		Zones   []zone   `json:"zones"`
		Records []record `json:"records"`
	} `json:"response"`
}
type zone struct {
	Name string `json:"name"`
}
type record struct {
	Name  string         `json:"name"`
	Type  string         `json:"type"`
	TTL   int            `json:"ttl"`
	RData map[string]any `json:"rData"`
}

func New(baseURL, zone string, credential dns.SecretRef) *Provider {
	return &Provider{Instance: dns.ProviderInstance{ID: "technitium", BaseURL: strings.TrimRight(baseURL, "/")}, Zone: strings.TrimSuffix(zone, "."), Credential: credential, Client: &http.Client{Timeout: 10 * time.Second}}
}
func (p *Provider) ID() string          { return "technitium" }
func (p *Provider) DisplayName() string { return "Technitium DNS Server" }
func (p *Provider) Detect(ctx context.Context) ([]dns.ProviderInstance, error) {
	if _, e := p.zones(ctx); e != nil {
		return nil, e
	}
	return []dns.ProviderInstance{p.Instance}, nil
}
func (p *Provider) Validate(ctx context.Context, _ dns.ProviderInstance, credential dns.SecretRef) error {
	if credential != "" {
		p.Credential = credential
	}
	_, e := p.zones(ctx)
	return e
}
func (p *Provider) Capabilities(context.Context, dns.ProviderInstance) (dns.Capabilities, error) {
	return dns.Capabilities{SupportsA: true, SupportsAAAA: true, SupportsCNAME: true, SupportsPTR: true, SupportsSRV: true, SupportsTXT: true, SupportsZones: true}, nil
}
func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.DNSRecord, error) {
	zones := []string{strings.TrimSuffix(zone, ".")}
	if zones[0] == "" {
		if p.Zone != "" {
			zones[0] = p.Zone
		} else {
			all, e := p.zones(ctx)
			if e != nil {
				return nil, e
			}
			zones = all
		}
	}
	out := []dns.DNSRecord{}
	for _, z := range zones {
		items, e := p.recordsForZone(ctx, z)
		if e != nil {
			return nil, e
		}
		out = append(out, items...)
	}
	return out, nil
}
func (p *Provider) recordsForZone(ctx context.Context, zone string) ([]dns.DNSRecord, error) {
	if zone == "" {
		return nil, fmt.Errorf("Technitium zone is required")
	}
	q := url.Values{}
	q.Set("domain", zone)
	q.Set("zone", zone)
	q.Set("listZone", "true")
	var res apiResponse
	if e := p.call(ctx, "/api/zones/records/get", q, &res); e != nil {
		return nil, e
	}
	out := []dns.DNSRecord{}
	for _, r := range res.Response.Records {
		t := dns.RecordType(strings.ToUpper(r.Type))
		switch t {
		case dns.RecordA, dns.RecordAAAA, dns.RecordCNAME, dns.RecordPTR, dns.RecordSRV, dns.RecordTXT:
		default:
			continue
		}
		out = append(out, dns.DNSRecord{ID: uuid.NewString(), ProviderID: p.ID(), Zone: zone, Name: strings.TrimSuffix(strings.ToLower(r.Name), "."), Type: t, Value: rdataValue(t, r.RData), TTL: time.Duration(r.TTL) * time.Second, Managed: false})
	}
	return out, nil
}
func rdataValue(t dns.RecordType, r map[string]any) string {
	switch t {
	case dns.RecordA, dns.RecordAAAA:
		return text(r["ipAddress"])
	case dns.RecordCNAME:
		return text(r["cname"])
	case dns.RecordPTR:
		return text(r["ptrName"])
	case dns.RecordSRV:
		return fmt.Sprintf("%d %d %d %s", number(r["priority"]), number(r["weight"]), number(r["port"]), text(r["target"]))
	case dns.RecordTXT:
		if v, ok := r["text"].([]any); ok {
			parts := make([]string, 0, len(v))
			for _, x := range v {
				parts = append(parts, text(x))
			}
			return strings.Join(parts, " ")
		}
		return text(r["text"])
	}
	return ""
}
func text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}
func number(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		n, _ := strconv.Atoi(x)
		return n
	default:
		return 0
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
	switch c.Type {
	case dns.ChangeCreate:
		return p.add(ctx, c.Record)
	case dns.ChangeDelete:
		return p.remove(ctx, c.Record)
	case dns.ChangeUpdate:
		if c.Previous == nil {
			return fmt.Errorf("update lacks previous record")
		}
		if e := p.remove(ctx, *c.Previous); e != nil {
			return e
		}
		return p.add(ctx, c.Record)
	}
	return fmt.Errorf("unsupported change %s", c.Type)
}
func (p *Provider) add(ctx context.Context, r dns.DNSRecord) error {
	q := url.Values{}
	q.Set("domain", r.Name)
	q.Set("zone", p.zoneFor(r))
	q.Set("type", string(r.Type))
	q.Set("value", r.Value)
	if r.TTL > 0 {
		q.Set("ttl", strconv.Itoa(int(r.TTL.Seconds())))
	}
	var res apiResponse
	return p.call(ctx, "/api/zones/records/add", q, &res)
}
func (p *Provider) remove(ctx context.Context, r dns.DNSRecord) error {
	q := url.Values{}
	q.Set("domain", r.Name)
	q.Set("zone", p.zoneFor(r))
	q.Set("type", string(r.Type))
	q.Set("value", r.Value)
	var res apiResponse
	return p.call(ctx, "/api/zones/records/delete", q, &res)
}
func (p *Provider) zoneFor(r dns.DNSRecord) string {
	if p.Zone != "" {
		return p.Zone
	}
	return strings.TrimSuffix(r.Zone, ".")
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
				status, evidence = dns.CheckPass, "Technitium contains expected record"
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
			if e := p.remove(ctx, c.Record); e != nil {
				return e
			}
		case dns.ChangeDelete:
			if c.Previous != nil {
				if e := p.add(ctx, *c.Previous); e != nil {
					return e
				}
			}
		case dns.ChangeUpdate:
			if e := p.remove(ctx, c.Record); e != nil {
				return e
			}
			if c.Previous != nil {
				if e := p.add(ctx, *c.Previous); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func (p *Provider) zones(ctx context.Context) ([]string, error) {
	var res apiResponse
	if e := p.call(ctx, "/api/zones/list", nil, &res); e != nil {
		return nil, e
	}
	out := []string{}
	for _, z := range res.Response.Zones {
		if z.Name != "" {
			out = append(out, strings.TrimSuffix(z.Name, "."))
		}
	}
	return out, nil
}
func (p *Provider) call(ctx context.Context, path string, q url.Values, out *apiResponse) error {
	if q == nil {
		q = url.Values{}
	}
	token := ""
	if p.Credential != "" {
		var e error
		token, e = secrets.Resolve(p.Credential)
		if e != nil {
			return e
		}
		q.Set("token", token)
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, p.Instance.BaseURL+path+"?"+q.Encode(), nil)
	if e != nil {
		return e
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r, e := p.Client.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusUnauthorized || r.StatusCode == http.StatusForbidden {
		return fmt.Errorf("Technitium authentication failed")
	}
	if r.StatusCode >= 300 {
		return fmt.Errorf("Technitium %s: %s", path, r.Status)
	}
	if e = json.NewDecoder(r.Body).Decode(out); e != nil {
		return e
	}
	if out.Status != "" && !strings.EqualFold(out.Status, "ok") {
		return fmt.Errorf("Technitium %s: %s", path, out.ErrorMessage)
	}
	return nil
}
