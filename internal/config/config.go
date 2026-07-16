package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version        int            `yaml:"version"`
	Installation   Installation   `yaml:"installation"`
	Domain         Domain         `yaml:"domain"`
	Provider       Provider       `yaml:"provider"`
	Discovery      Discovery      `yaml:"discovery"`
	Naming         Naming         `yaml:"naming"`
	Reconciliation Reconciliation `yaml:"reconciliation"`
	Verification   Verification   `yaml:"verification"`
}
type Installation struct {
	Name          string `yaml:"name"`
	DataDirectory string `yaml:"data_directory"`
}
type Domain struct {
	Zone       string        `yaml:"zone"`
	DefaultTTL time.Duration `yaml:"default_ttl"`
	CreateIPv4 bool          `yaml:"create_ipv4"`
	CreateIPv6 bool          `yaml:"create_ipv6"`
	CreatePTR  bool          `yaml:"create_ptr"`
}
type Credentials struct {
	SecretRef string `yaml:"secret_ref"`
}
type Provider struct {
	Type        string      `yaml:"type"`
	BaseURL     string      `yaml:"base_url"`
	Credentials Credentials `yaml:"credentials"`
}
type Docker struct {
	Enabled       bool     `yaml:"enabled"`
	Socket        string   `yaml:"socket"`
	HostAddresses []string `yaml:"host_addresses"`
}
type Discovery struct {
	Docker Docker `yaml:"docker"`
}
type Naming struct {
	ServiceTemplate   string `yaml:"service_template"`
	HostTemplate      string `yaml:"host_template"`
	CollisionStrategy string `yaml:"collision_strategy"`
}
type Reconciliation struct {
	Interval         time.Duration `yaml:"interval"`
	StaleGracePeriod time.Duration `yaml:"stale_grace_period"`
	AutomaticUpdates bool          `yaml:"automatic_updates"`
	AutomaticDeletes bool          `yaml:"automatic_deletes"`
}
type Verification struct {
	DirectDNSServer string        `yaml:"direct_dns_server"`
	SystemResolver  bool          `yaml:"system_resolver"`
	Timeout         time.Duration `yaml:"timeout"`
}

func Default() Config {
	return Config{Version: 1, Installation: Installation{Name: "home-lab", DataDirectory: "./.labdns"}, Domain: Domain{Zone: "home.arpa", DefaultTTL: 5 * time.Minute, CreateIPv4: true}, Provider: Provider{Type: "pihole"}, Discovery: Discovery{Docker: Docker{Enabled: true, Socket: "unix:///var/run/docker.sock"}}, Naming: Naming{ServiceTemplate: "{{ .Service }}.{{ .Zone }}", HostTemplate: "{{ .Host }}.{{ .Zone }}", CollisionStrategy: "suffix-host"}, Reconciliation: Reconciliation{Interval: 5 * time.Minute, StaleGracePeriod: 24 * time.Hour, AutomaticUpdates: true}, Verification: Verification{Timeout: 5 * time.Second, SystemResolver: true}}
}
func Load(path string) (Config, error) {
	c := Default()
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if e = yaml.Unmarshal(b, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	var errs []string
	if c.Version != 1 {
		errs = append(errs, "version: only version 1 is supported")
	}
	if !validZone(c.Domain.Zone) {
		errs = append(errs, "domain.zone: invalid DNS zone")
	}
	if c.Domain.DefaultTTL < 30*time.Second {
		errs = append(errs, "domain.default_ttl: must be at least 30 seconds")
	}
	if c.Provider.Type == "" {
		errs = append(errs, "provider.type: required")
	}
	if c.Provider.BaseURL != "" {
		u, e := url.ParseRequestURI(c.Provider.BaseURL)
		if e != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, "provider.base_url: invalid URL")
		}
	}
	if c.Verification.Timeout <= 0 {
		errs = append(errs, "verification.timeout: must be positive")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
func validZone(z string) bool {
	z = strings.TrimSuffix(strings.ToLower(z), ".")
	if z == "" || len(z) > 253 || z == "local" {
		return false
	}
	for _, l := range strings.Split(z, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
