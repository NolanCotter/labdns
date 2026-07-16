package secrets

import (
	"fmt"
	"github.com/labdns/labdns/internal/dns"
	"os"
	"strings"
)

func Resolve(ref dns.SecretRef) (string, error) {
	s := string(ref)
	if strings.HasPrefix(s, "env:") {
		v := os.Getenv(strings.TrimPrefix(s, "env:"))
		if v == "" {
			return "", fmt.Errorf("secret not found: %s", s)
		}
		return v, nil
	}
	return "", fmt.Errorf("unsupported secret reference %q; use env:NAME until keyring support is configured", s)
}
func Redact(s string) string {
	if len(s) < 5 {
		return "[REDACTED]"
	}
	return s[:2] + "…" + s[len(s)-2:]
}
