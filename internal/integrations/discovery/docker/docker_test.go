package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	containers := []summary{
		{ID: "one", Names: []string{"/web"}, Labels: map[string]string{"com.docker.compose.service": "web"}, Ports: []struct {
			PrivatePort uint16 `json:"PrivatePort"`
			PublicPort  uint16 `json:"PublicPort"`
			Type        string `json:"Type"`
		}{{PrivatePort: 8080, PublicPort: 8080, Type: "tcp"}}},
		{ID: "two", Names: []string{"/host"}},
		{ID: "three", Names: []string{"/internal"}, Labels: map[string]string{"com.docker.compose.project": "lab"}},
	}
	inspections := map[string]inspect{
		"one":   {},
		"two":   {HostConfig: struct {
			NetworkMode string `json:"NetworkMode"`
		}{NetworkMode: "host"}},
		"three": {},
	}
	inspections["three"].NetworkSettings.Networks = map[string]struct {
		IPAddress         string `json:"IPAddress"`
		GlobalIPv6Address string `json:"GlobalIPv6Address"`
	}{"lab": {IPAddress: "172.18.0.3", GlobalIPv6Address: "fd00::3"}}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/containers/json":
			_ = json.NewEncoder(w).Encode(containers)
		case strings.HasPrefix(r.URL.Path, "/containers/"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
			_ = json.NewEncoder(w).Encode(inspections[id])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestDiscover(t *testing.T) {
	srv := newServer(t)
	d := Discoverer{
		HostAddresses:     []netip.Addr{netip.MustParseAddr("10.0.0.20")},
		HostIPv6Addresses: []netip.Addr{netip.MustParseAddr("fd00::20")},
		Client:            srv.Client(),
		BaseURL:           srv.URL,
	}
	services, e := d.Discover(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(services) != 3 {
		t.Fatalf("got %d services", len(services))
	}
	if services[0].Name != "web" || services[0].ComposeService != "web" || services[0].Metadata["address_class"] != "host-published" {
		t.Fatalf("published service = %#v", services[0])
	}
	if services[0].IPv4Addresses[0].String() != "10.0.0.20" || services[0].IPv6Addresses[0].String() != "fd00::20" {
		t.Fatalf("host addresses = %#v", services[0])
	}
	if services[1].Metadata["address_class"] != "host-network" {
		t.Fatalf("host service = %#v", services[1])
	}
	if services[2].IPv4Addresses[0].String() != "172.18.0.3" || services[2].IPv6Addresses[0].String() != "fd00::3" {
		t.Fatalf("container addresses = %#v", services[2])
	}
	if services[2].Metadata["address_class"] != "container-only" {
		t.Fatalf("container class = %#v", services[2].Metadata)
	}
	if services[2].ComposeProject != "lab" {
		t.Fatalf("compose project = %#v", services[2])
	}
}

func TestDiscoverErrors(t *testing.T) {
	if _, e := (Discoverer{Socket: "http://nope"}).Discover(context.Background()); e == nil {
		t.Fatal("expected unsupported socket error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := Discoverer{Client: srv.Client(), BaseURL: srv.URL}
	if _, e := d.Discover(context.Background()); e == nil || !strings.Contains(e.Error(), "list Docker containers") {
		t.Fatalf("got %v", e)
	}
}
