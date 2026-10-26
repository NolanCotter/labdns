package app

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/labdns/labdns/internal/audit"
	"github.com/labdns/labdns/internal/config"
	"github.com/labdns/labdns/internal/dns"
	dockerdiscovery "github.com/labdns/labdns/internal/integrations/discovery/docker"
	"github.com/labdns/labdns/internal/integrations/providers/adguard"
	"github.com/labdns/labdns/internal/integrations/providers/hostsfile"
	"github.com/labdns/labdns/internal/integrations/providers/pihole"
	"github.com/labdns/labdns/internal/integrations/providers/rfc2136"
	"github.com/labdns/labdns/internal/integrations/providers/technitium"
	"github.com/labdns/labdns/internal/naming"
	"github.com/labdns/labdns/internal/records"
	"github.com/labdns/labdns/internal/state"
	"github.com/labdns/labdns/internal/transaction"
	"github.com/labdns/labdns/internal/verification"
)

type App struct {
	Config   config.Config
	Store    *state.Store
	Provider dns.Provider
}
type Plan struct {
	Services []dns.Service       `json:"services"`
	Desired  []dns.DesiredRecord `json:"desired"`
	Changes  []dns.Change        `json:"changes"`
}
type Check struct {
	Name     string `json:"name" yaml:"name"`
	Status   string `json:"status" yaml:"status"`
	Evidence string `json:"evidence" yaml:"evidence"`
}
type Report struct {
	OK     bool    `json:"ok" yaml:"ok"`
	Checks []Check `json:"checks" yaml:"checks"`
}
type RepairReport struct {
	InterruptedTransactions int64    `json:"interrupted_transactions" yaml:"interrupted_transactions"`
	Actions                 []string `json:"actions" yaml:"actions"`
}
type Export struct {
	Version      int          `json:"version" yaml:"version"`
	ExportedAt   time.Time    `json:"exported_at" yaml:"exported_at"`
	Installation string       `json:"installation" yaml:"installation"`
	Provider     string       `json:"provider" yaml:"provider"`
	Domain       string       `json:"domain" yaml:"domain"`
	State        state.Export `json:"state" yaml:"state"`
}

func New(c config.Config) (*App, error) {
	s, e := state.Open(c.Installation.DataDirectory)
	if e != nil {
		return nil, e
	}
	var p dns.Provider
	zone := c.Provider.Zone
	if zone == "" {
		zone = c.Domain.Zone
	}
	switch c.Provider.Type {
	case "pihole":
		p = pihole.New(c.Provider.BaseURL, dns.SecretRef(c.Provider.Credentials.SecretRef))
	case "adguard":
		p = adguard.New(c.Provider.BaseURL, c.Provider.Credentials.Username, dns.SecretRef(c.Provider.Credentials.SecretRef))
	case "technitium":
		p = technitium.New(c.Provider.BaseURL, zone, dns.SecretRef(c.Provider.Credentials.SecretRef))
	case "rfc2136":
		p = rfc2136.New(c.Provider.Server, zone, c.Provider.TSIGKey, c.Provider.TSIGAlgorithm, dns.SecretRef(c.Provider.TSIGSecretRef))
	case "hostsfile":
		p = hostsfile.New(c.Provider.HostsFile)
	default:
		s.Close()
		return nil, fmt.Errorf("provider %q is not implemented in this build", c.Provider.Type)
	}
	return &App{Config: c, Store: s, Provider: p}, nil
}
func (a *App) Close() error { return a.Store.Close() }
func (a *App) Discover(ctx context.Context) ([]dns.Service, error) {
	if !a.Config.Discovery.Docker.Enabled {
		return nil, nil
	}
	addrs := []netip.Addr{}
	for _, v := range a.Config.Discovery.Docker.HostAddresses {
		ip, e := netip.ParseAddr(v)
		if e != nil {
			return nil, fmt.Errorf("discovery.docker.host_addresses: %w", e)
		}
		if !safeTarget(ip) {
			return nil, fmt.Errorf("discovery.docker.host_addresses: unsafe target %s", ip)
		}
		addrs = append(addrs, ip)
	}
	v6 := []netip.Addr{}
	for _, v := range a.Config.Discovery.Docker.HostIPv6Addresses {
		ip, e := netip.ParseAddr(v)
		if e != nil {
			return nil, fmt.Errorf("discovery.docker.host_ipv6_addresses: %w", e)
		}
		if !safeTarget(ip) {
			return nil, fmt.Errorf("discovery.docker.host_ipv6_addresses: unsafe target %s", ip)
		}
		v6 = append(v6, ip)
	}
	return (dockerdiscovery.Discoverer{Socket: a.Config.Discovery.Docker.Socket, HostAddresses: addrs, HostIPv6Addresses: v6}).Discover(ctx)
}
func (a *App) CreatePlan(ctx context.Context) (Plan, error) {
	services, e := a.Discover(ctx)
	if e != nil {
		return Plan{}, e
	}
	desired, e := a.Desired(services)
	if e != nil {
		return Plan{}, e
	}
	zones := map[string]bool{a.Config.Domain.Zone: true}
	for _, d := range desired {
		zones[d.Zone] = true
	}
	existing := []dns.DNSRecord{}
	seen := map[string]bool{}
	for zone := range zones {
		items, e := a.Provider.ListRecords(ctx, zone)
		if e != nil {
			return Plan{}, e
		}
		for _, r := range items {
			k := strings.ToLower(r.Name) + "|" + string(r.Type) + "|" + r.Value
			if seen[k] {
				continue
			}
			seen[k] = true
			existing = append(existing, r)
		}
	}
	for i := range existing {
		managed, e := a.Store.IsManaged(a.Provider.ID(), existing[i].Zone, existing[i].Name, string(existing[i].Type))
		if e != nil {
			return Plan{}, e
		}
		existing[i].Managed = existing[i].Managed || managed
	}
	changes, e := a.Provider.Plan(ctx, desired, existing)
	return Plan{Services: services, Desired: desired, Changes: changes}, e
}
func (a *App) Desired(services []dns.Service) ([]dns.DesiredRecord, error) {
	used := map[string]bool{}
	engine := naming.Engine{Zone: a.Config.Domain.Zone, CollisionStrategy: a.Config.Naming.CollisionStrategy}
	out := []dns.DesiredRecord{}
	ptrSeen := map[string]bool{}
	for i := range services {
		s := &services[i]
		if s.Metadata["address_class"] == "container-only" {
			continue
		}
		if len(s.IPv4Addresses) == 0 && len(s.IPv6Addresses) == 0 {
			continue
		}
		name, e := engine.Suggest(preferredName(*s), s.HostID, used)
		if e != nil {
			return nil, e
		}
		used[name] = true
		s.SuggestedNames = []string{name}
		addresses := []dns.DesiredRecord{}
		if a.Config.Domain.CreateIPv4 && len(s.IPv4Addresses) > 0 {
			addresses = append(addresses, dns.DesiredRecord{ServiceID: s.ID, Zone: a.Config.Domain.Zone, Name: name, Type: dns.RecordA, Value: s.IPv4Addresses[0].String(), TTL: a.Config.Domain.DefaultTTL})
		}
		if a.Config.Domain.CreateIPv6 && len(s.IPv6Addresses) > 0 {
			addresses = append(addresses, dns.DesiredRecord{ServiceID: s.ID, Zone: a.Config.Domain.Zone, Name: name, Type: dns.RecordAAAA, Value: s.IPv6Addresses[0].String(), TTL: a.Config.Domain.DefaultTTL})
		}
		out = append(out, addresses...)
		if a.Config.Domain.CreateTXT && len(addresses) > 0 {
			out = append(out, dns.DesiredRecord{ServiceID: s.ID, Zone: a.Config.Domain.Zone, Name: name, Type: dns.RecordTXT, Value: fmt.Sprintf("managed-by=labdns service=%s source=%s", name, s.Source), TTL: a.Config.Domain.DefaultTTL})
		}
		if a.Config.Domain.CreateSRV {
			for _, port := range srvPorts(*s, name, a.Config.Domain.Zone) {
				out = append(out, dns.DesiredRecord{ServiceID: s.ID, Zone: a.Config.Domain.Zone, Name: port.name, Type: dns.RecordSRV, Value: port.value, TTL: a.Config.Domain.DefaultTTL})
			}
		}
		if a.Config.Domain.CreatePTR && a.Config.Domain.PTRZone != "" {
			for _, d := range addresses {
				if !isAddressType(d.Type) {
					continue
				}
				ip, err := netip.ParseAddr(d.Value)
				if err != nil {
					continue
				}
				reverse := reverseName(ip)
				zone := strings.TrimSuffix(strings.ToLower(a.Config.Domain.PTRZone), ".")
				if reverse != zone && !strings.HasSuffix(reverse, "."+zone) {
					continue
				}
				k := reverse + "|" + name
				if ptrSeen[k] {
					continue
				}
				ptrSeen[k] = true
				out = append(out, dns.DesiredRecord{ServiceID: s.ID, Zone: zone, Name: reverse, Type: dns.RecordPTR, Value: name, TTL: a.Config.Domain.DefaultTTL})
			}
		}
	}
	return out, nil
}

type srvRecord struct{ name, value string }

func srvPorts(s dns.Service, target, zone string) []srvRecord {
	label := strings.Split(target, ".")[0]
	seen := map[string]bool{}
	out := []srvRecord{}
	for _, p := range s.Ports {
		if p.Port == 0 {
			continue
		}
		proto := strings.ToLower(p.Protocol)
		if proto != "udp" {
			proto = "tcp"
		}
		name := fmt.Sprintf("_%s._%s.%s", label, proto, strings.TrimSuffix(zone, "."))
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, srvRecord{name: name, value: fmt.Sprintf("0 0 %d %s", p.Port, target)})
	}
	return out
}
func isAddressType(t dns.RecordType) bool { return t == dns.RecordA || t == dns.RecordAAAA }
func reverseName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	parts := make([]string, 0, 32)
	for i := len(b) - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", b[i]&0x0f), fmt.Sprintf("%x", b[i]>>4))
	}
	return strings.Join(parts, ".") + ".ip6.arpa"
}
func preferredName(s dns.Service) string {
	for k, v := range s.Labels {
		if strings.Contains(k, "traefik.http.routers") && strings.HasSuffix(k, ".rule") && strings.Contains(v, "Host(`") {
			x := strings.Split(strings.TrimPrefix(strings.Split(v, "Host(`")[1], "`"), ".")[0]
			if x != "" {
				return x
			}
		}
	}
	return s.Name
}
func safeTarget(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}
func (a *App) Apply(ctx context.Context, plan Plan) (transaction.Result, error) {
	if records.HasBlocking(plan.Changes) {
		return transaction.Result{}, fmt.Errorf("plan contains unresolved conflicts")
	}
	res, e := transaction.Apply(ctx, a.Store, a.Provider, plan.Changes, plan.Desired, func(ctx context.Context, d []dns.DesiredRecord) []dns.CheckResult {
		return verification.Direct(ctx, a.Config.Verification.DirectDNSServer, d, a.Config.Verification.Timeout)
	})
	if e != nil {
		return res, e
	}
	now := time.Now().UTC()
	if e = a.Store.ReconcileManaged(a.Provider.ID(), plan.Desired, now); e != nil {
		return res, e
	}
	for _, c := range plan.Changes {
		if c.Type == dns.ChangeNoChange {
			continue
		}
		_ = audit.Log(ctx, a.Store, audit.Event{Type: "record_" + string(c.Type), Actor: "cli", Provider: a.Provider.ID(), RecordName: c.Record.Name, RecordType: string(c.Record.Type), PreviousValue: valueOf(c.Previous), NewValue: c.Record.Value, Result: "success", Reason: c.Reason, TransactionID: res.ID})
	}
	return res, nil
}
func valueOf(r *dns.DNSRecord) string {
	if r == nil {
		return ""
	}
	return r.Value
}

// Stale lists managed records that have been absent from discovery for the
// configured grace period.
func (a *App) Stale(ctx context.Context, olderThan time.Time) ([]dns.DNSRecord, error) {
	_ = ctx
	return a.Store.StaleRecords(a.Provider.ID(), olderThan)
}

func (a *App) Prune(ctx context.Context, olderThan time.Time) (transaction.Result, []dns.DNSRecord, error) {
	stale, e := a.Stale(ctx, olderThan)
	if e != nil {
		return transaction.Result{}, nil, e
	}
	changes := make([]dns.Change, 0, len(stale))
	for i := range stale {
		r := stale[i]
		changes = append(changes, dns.Change{ID: fmt.Sprintf("prune-%d", i), Type: dns.ChangeDelete, Record: r, Previous: &r, Reason: "stale managed record exceeded grace period", Destructive: true})
	}
	if len(changes) == 0 {
		return transaction.Result{}, stale, nil
	}
	res, e := transaction.Apply(ctx, a.Store, a.Provider, changes, nil, func(context.Context, []dns.DesiredRecord) []dns.CheckResult { return nil })
	if e != nil {
		return res, stale, e
	}
	for _, c := range changes {
		_ = a.Store.RemoveManaged(a.Provider.ID(), c.Record.Zone, c.Record.Name, string(c.Record.Type))
		_ = audit.Log(ctx, a.Store, audit.Event{Type: "record_delete", Actor: "cli", Provider: a.Provider.ID(), RecordName: c.Record.Name, RecordType: string(c.Record.Type), PreviousValue: c.Record.Value, Result: "success", Reason: c.Reason, TransactionID: res.ID})
	}
	return res, stale, nil
}
func (a *App) Adopt(ctx context.Context, name string, typ dns.RecordType, serviceID string) (dns.DNSRecord, error) {
	items, e := a.Provider.ListRecords(ctx, a.Config.Domain.Zone)
	if e != nil {
		return dns.DNSRecord{}, e
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, r := range items {
		if strings.EqualFold(strings.TrimSuffix(r.Name, "."), name) && (typ == "" || r.Type == typ) {
			if e = a.Store.MarkManaged(a.Provider.ID(), r.Zone, r.Name, string(r.Type), r.Value, serviceID); e != nil {
				return r, e
			}
			r.Managed = true
			return r, nil
		}
	}
	return dns.DNSRecord{}, fmt.Errorf("record %s was not found at provider %s", name, a.Provider.ID())
}
func (a *App) Doctor(ctx context.Context) Report {
	report := Report{OK: true, Checks: []Check{}}
	add := func(name, status, evidence string) {
		if status == "fail" {
			report.OK = false
		}
		report.Checks = append(report.Checks, Check{Name: name, Status: status, Evidence: evidence})
	}
	if e := a.Config.Validate(); e != nil {
		add("configuration", "fail", e.Error())
	} else {
		add("configuration", "pass", "configuration is valid")
	}
	if e := a.Store.IntegrityCheck(); e != nil {
		add("state database", "fail", e.Error())
	} else {
		add("state database", "pass", "SQLite integrity check passed")
	}
	instances, e := a.Provider.Detect(ctx)
	if e != nil {
		add("provider detection", "fail", e.Error())
	} else {
		add("provider detection", "pass", fmt.Sprintf("%s detected at %s", a.Provider.DisplayName(), instances[0].BaseURL))
		if e = a.Provider.Validate(ctx, instances[0], ""); e != nil {
			add("provider authentication", "fail", e.Error())
		} else {
			add("provider authentication", "pass", "provider accepted configuration")
		}
		caps, e := a.Provider.Capabilities(ctx, instances[0])
		if e != nil {
			add("provider capabilities", "fail", e.Error())
		} else if missing := missingCapabilities(a.Config, caps); missing != "" {
			add("provider capabilities", "fail", "provider does not support requested records: "+missing)
		} else {
			add("provider capabilities", "pass", "provider supports requested record types")
		}
	}
	if a.Config.Verification.DirectDNSServer == "" {
		add("direct DNS verification", "warn", "verification.direct_dns_server is not configured; apply will warn instead of verifying")
	} else if e := verification.Probe(ctx, a.Config.Verification.DirectDNSServer, a.Config.Verification.Timeout); e != nil {
		add("direct DNS verification", "fail", e.Error())
	} else {
		add("direct DNS verification", "pass", "DNS server answered a query")
	}
	return report
}
func missingCapabilities(c config.Config, caps dns.Capabilities) string {
	missing := []string{}
	if c.Domain.CreateIPv4 && !caps.SupportsA {
		missing = append(missing, "A")
	}
	if c.Domain.CreateIPv6 && !caps.SupportsAAAA {
		missing = append(missing, "AAAA")
	}
	if c.Domain.CreatePTR && !caps.SupportsPTR {
		missing = append(missing, "PTR")
	}
	if c.Domain.CreateSRV && !caps.SupportsSRV {
		missing = append(missing, "SRV")
	}
	if c.Domain.CreateTXT && !caps.SupportsTXT {
		missing = append(missing, "TXT")
	}
	return strings.Join(missing, ", ")
}
func (a *App) Repair(ctx context.Context, olderThan time.Time) (RepairReport, error) {
	_ = ctx
	out := RepairReport{Actions: []string{}}
	n, e := a.Store.InterruptStaleTransactions(olderThan)
	if e != nil {
		return out, e
	}
	out.InterruptedTransactions = n
	if n > 0 {
		out.Actions = append(out.Actions, fmt.Sprintf("marked %d stale running transaction(s) as interrupted", n))
	}
	if e = a.Store.IntegrityCheck(); e != nil {
		return out, e
	}
	out.Actions = append(out.Actions, "state database integrity check passed")
	return out, nil
}
func (a *App) Export() (Export, error) {
	s, e := a.Store.Export()
	return Export{Version: 1, ExportedAt: time.Now().UTC(), Installation: a.Config.Installation.Name, Provider: a.Provider.ID(), Domain: a.Config.Domain.Zone, State: s}, e
}
func (a *App) Backup(path string) error { return a.Store.Backup(path) }

func (a *App) InitConfig(path string) error {
	if _, e := os.Stat(path); e == nil {
		return fmt.Errorf("refusing to overwrite existing config %s", path)
	}
	return os.WriteFile(path, []byte("version: 1\ninstallation:\n  name: home-lab\n  data_directory: ./.labdns\ndomain:\n  zone: home.arpa\n  default_ttl: 5m\n  create_ipv4: true\nprovider:\n  type: pihole\n  base_url: http://10.0.0.2\n  credentials:\n    secret_ref: env:LABDNS_PIHOLE_TOKEN\ndiscovery:\n  docker:\n    enabled: true\n    socket: unix:///var/run/docker.sock\n    host_addresses: [10.0.0.20]\nverification:\n  direct_dns_server: 10.0.0.2:53\n"), 0600)
}
