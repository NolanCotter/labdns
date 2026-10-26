package secrets

import (
	"strings"
	"testing"

	"github.com/labdns/labdns/internal/dns"
)

func TestResolveEnv(t *testing.T) {
	t.Setenv("LABDNS_TEST_TOKEN", "s3cret")
	got, e := Resolve("env:LABDNS_TEST_TOKEN")
	if e != nil || got != "s3cret" {
		t.Fatalf("got %q, %v", got, e)
	}
}
func TestResolveErrors(t *testing.T) {
	if _, e := Resolve("env:LABDNS_MISSING_TOKEN"); e == nil {
		t.Fatal("expected missing secret error")
	}
	if _, e := Resolve("keyring:foo"); e == nil || !strings.Contains(e.Error(), "unsupported secret reference") {
		t.Fatalf("got %v", e)
	}
}
func TestRedact(t *testing.T) {
	if got := Redact("short"); got != "[REDACTED]" {
		t.Fatalf("short value got %q", got)
	}
	got := Redact("abcdefgh")
	if got == "abcdefgh" || !strings.HasPrefix(got, "ab") || !strings.HasSuffix(got, "gh") {
		t.Fatalf("got %q", got)
	}
	var _ dns.SecretRef = "env:X"
}
