// Package docker discovers containers through Docker Engine's documented HTTP API.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/dns"
)

type Discoverer struct {
	Socket        string
	HostAddresses []netip.Addr
}
type summary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
	Ports  []struct {
		PrivatePort uint16 `json:"PrivatePort"`
		PublicPort  uint16 `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}
type inspect struct {
	ID         string `json:"Id"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func (d Discoverer) Discover(ctx context.Context) ([]dns.Service, error) {
	c, e := d.client()
	if e != nil {
		return nil, e
	}
	var containers []summary
	if e = d.get(ctx, c, "/containers/json?all=false", &containers); e != nil {
		return nil, fmt.Errorf("list Docker containers: %w", e)
	}
	out := make([]dns.Service, 0, len(containers))
	for _, container := range containers {
		var in inspect
		if e = d.get(ctx, c, "/containers/"+container.ID+"/json", &in); e != nil {
			return nil, fmt.Errorf("inspect %s: %w", container.ID, e)
		}
		out = append(out, d.service(container, in))
	}
	return out, nil
}
func (d Discoverer) client() (*http.Client, error) {
	socket := d.Socket
	if socket == "" {
		socket = "unix:///var/run/docker.sock"
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	switch {
	case strings.HasPrefix(socket, "unix://"):
		path := strings.TrimPrefix(socket, "unix://")
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}
	case strings.HasPrefix(socket, "tcp://"):
	default:
		return nil, fmt.Errorf("unsupported Docker endpoint %q; use unix:// or tcp://", socket)
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: transport}, nil
}
func (d Discoverer) get(ctx context.Context, c *http.Client, path string, out any) error {
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if e != nil {
		return e
	}
	resp, e := c.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Docker API %s returned %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
func (d Discoverer) service(c summary, in inspect) dns.Service {
	name := "unknown"
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}
	labels := map[string]string{}
	for k, v := range c.Labels {
		labels[k] = v
	}
	ports := []dns.ServicePort{}
	published := false
	for _, p := range c.Ports {
		ports = append(ports, dns.ServicePort{Port: p.PrivatePort, Protocol: p.Type, Published: p.PublicPort != 0})
		published = published || p.PublicPort != 0
	}
	v4 := []netip.Addr{}
	if published || in.HostConfig.NetworkMode == "host" {
		v4 = append(v4, d.HostAddresses...)
	} else {
		for _, n := range in.NetworkSettings.Networks {
			if ip, e := netip.ParseAddr(n.IPAddress); e == nil && !ip.IsLoopback() {
				v4 = append(v4, ip)
			}
		}
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].Less(v4[j]) })
	if n := labels["com.docker.compose.service"]; n != "" {
		name = n
	}
	return dns.Service{ID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("docker:"+c.ID)).String(), Name: name, Source: dns.SourceDocker, HostID: "docker-host", IPv4Addresses: v4, Ports: ports, ContainerID: c.ID, ComposeProject: labels["com.docker.compose.project"], ComposeService: labels["com.docker.compose.service"], Labels: labels, Metadata: map[string]string{"address_class": addressClass(published, in.HostConfig.NetworkMode)}}
}
func addressClass(published bool, network string) string {
	if network == "host" {
		return "host-network"
	}
	if published {
		return "host-published"
	}
	return "container-only"
}
