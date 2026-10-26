package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRejectsLocalZone(t *testing.T) {
	c := Default()
	c.Domain.Zone = "local"
	if c.Validate() == nil {
		t.Fatal("expected invalid .local zone")
	}
}
func TestDefaultConfigIsValid(t *testing.T) {
	if e := Default().Validate(); e != nil {
		t.Fatal(e)
	}
}
func TestProviderValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"unsupported provider", func(c *Config) { c.Provider.Type = "bind" }, "provider.type"},
		{"pihole needs base url", func(c *Config) { c.Provider.BaseURL = "" }, "provider.base_url"},
		{"rfc2136 needs server", func(c *Config) { c.Provider.Type = "rfc2136" }, "provider.server"},
		{"rfc2136 server must be host port", func(c *Config) { c.Provider.Type = "rfc2136"; c.Provider.Server = "dns" }, "host:port"},
		{"hosts file needs path", func(c *Config) { c.Provider.Type = "hostsfile" }, "provider.hosts_file"},
		{"ptr needs zone", func(c *Config) { c.Domain.CreatePTR = true }, "domain.ptr_zone"},
		{"invalid ptr zone", func(c *Config) { c.Domain.CreatePTR = true; c.Domain.PTRZone = "bad_zone" }, "domain.ptr_zone"},
		{"invalid ttl", func(c *Config) { c.Domain.DefaultTTL = time.Second }, "default_ttl"},
		{"zero timeout", func(c *Config) { c.Verification.Timeout = 0 }, "verification.timeout"},
		{"invalid interval", func(c *Config) { c.Reconciliation.Interval = 0 }, "reconciliation.interval"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default()
			tt.edit(&c)
			e := c.Validate()
			if e == nil || !strings.Contains(e.Error(), tt.want) {
				t.Fatalf("got %v, want error containing %q", e, tt.want)
			}
		})
	}
}
func TestLoadDefaultsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "labdns.yaml")
	if e := os.WriteFile(path, []byte("version: 1\ndomain:\n  zone: lab.example\n  default_ttl: 1m\n  create_ipv6: true\nprovider:\n  type: hostsfile\n  hosts_file: /tmp/hosts\n"), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if c.Domain.Zone != "lab.example" || !c.Domain.CreateIPv6 || !c.Domain.CreateIPv4 || c.Provider.Type != "hostsfile" {
		t.Fatalf("unexpected config: %#v", c)
	}
	if c.Naming.CollisionStrategy != "suffix-host" {
		t.Fatalf("default not preserved: %#v", c.Naming)
	}
}
