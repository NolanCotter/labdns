package app

import (
	"context"
	"fmt"
	"github.com/labdns/labdns/internal/config"
	"github.com/labdns/labdns/internal/dns"
	dockerdiscovery "github.com/labdns/labdns/internal/integrations/discovery/docker"
	"github.com/labdns/labdns/internal/integrations/providers/pihole"
	"github.com/labdns/labdns/internal/naming"
	"github.com/labdns/labdns/internal/records"
	"github.com/labdns/labdns/internal/state"
	"github.com/labdns/labdns/internal/transaction"
	"github.com/labdns/labdns/internal/verification"
	"net/netip"
	"os"
	"strings"
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

func New(c config.Config) (*App, error) {
	s, e := state.Open(c.Installation.DataDirectory)
	if e != nil {
		return nil, e
	}
	var p dns.Provider
	switch c.Provider.Type {
	case "pihole":
		p = pihole.New(c.Provider.BaseURL, dns.SecretRef(c.Provider.Credentials.SecretRef))
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
	return (dockerdiscovery.Discoverer{Socket: a.Config.Discovery.Docker.Socket, HostAddresses: addrs}).Discover(ctx)
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
	existing, e := a.Provider.ListRecords(ctx, a.Config.Domain.Zone)
	if e != nil {
		return Plan{}, e
	}
	for i := range existing {
		managed, e := a.Store.IsManaged(a.Provider.ID(), existing[i].Zone, existing[i].Name, string(existing[i].Type))
		if e != nil {
			return Plan{}, e
		}
		existing[i].Managed = managed
	}
	changes, e := a.Provider.Plan(ctx, desired, existing)
	return Plan{Services: services, Desired: desired, Changes: changes}, e
}
func (a *App) Desired(services []dns.Service) ([]dns.DesiredRecord, error) {
	used := map[string]bool{}
	engine := naming.Engine{Zone: a.Config.Domain.Zone, CollisionStrategy: a.Config.Naming.CollisionStrategy}
	out := []dns.DesiredRecord{}
	for i := range services {
		s := &services[i]
		if s.Metadata["address_class"] == "container-only" {
			continue
		}
		if len(s.IPv4Addresses) == 0 {
			continue
		}
		name, e := engine.Suggest(preferredName(*s), s.HostID, used)
		if e != nil {
			return nil, e
		}
		used[name] = true
		s.SuggestedNames = []string{name}
		if a.Config.Domain.CreateIPv4 {
			out = append(out, dns.DesiredRecord{ServiceID: s.ID, Zone: a.Config.Domain.Zone, Name: name, Type: dns.RecordA, Value: s.IPv4Addresses[0].String(), TTL: a.Config.Domain.DefaultTTL})
		}
	}
	return out, nil
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
	if e == nil {
		for _, c := range plan.Changes {
			switch c.Type {
			case dns.ChangeCreate, dns.ChangeUpdate:
				_ = a.Store.MarkManaged(a.Provider.ID(), c.Record.Zone, c.Record.Name, string(c.Record.Type), c.Record.Value, c.Record.SourceID)
			case dns.ChangeDelete:
				_ = a.Store.RemoveManaged(a.Provider.ID(), c.Record.Zone, c.Record.Name, string(c.Record.Type))
			}
		}
	}
	return res, e
}
func (a *App) InitConfig(path string) error {
	if _, e := os.Stat(path); e == nil {
		return fmt.Errorf("refusing to overwrite existing config %s", path)
	}
	return os.WriteFile(path, []byte("version: 1\ninstallation:\n  name: home-lab\n  data_directory: ./.labdns\ndomain:\n  zone: home.arpa\n  default_ttl: 5m\n  create_ipv4: true\nprovider:\n  type: pihole\n  base_url: http://10.0.0.2\n  credentials:\n    secret_ref: env:LABDNS_PIHOLE_TOKEN\ndiscovery:\n  docker:\n    enabled: true\n    socket: unix:///var/run/docker.sock\n    host_addresses: [10.0.0.20]\nverification:\n  direct_dns_server: 10.0.0.2:53\n"), 0600)
}
