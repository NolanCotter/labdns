package naming

import (
	"fmt"
	"strings"
	"unicode"
)

type Engine struct{ Zone, CollisionStrategy string }

func NormalizeLabel(in string) string {
	var b strings.Builder
	hyphen := false
	for _, r := range strings.ToLower(strings.TrimSpace(in)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			hyphen = false
		} else if !hyphen {
			b.WriteByte('-')
			hyphen = true
		}
	}
	return strings.Trim(b.String(), "-")
}
func (e Engine) Suggest(service, host string, used map[string]bool) (string, error) {
	base := NormalizeLabel(service)
	if base == "" {
		return "", fmt.Errorf("service name %q normalizes to empty", service)
	}
	if len(base) > 63 {
		base = base[:63]
		base = strings.TrimRight(base, "-")
	}
	candidate := base + "." + strings.TrimSuffix(e.Zone, ".")
	if len(candidate) > 253 {
		return "", fmt.Errorf("resulting DNS name is too long")
	}
	if !used[candidate] {
		return candidate, nil
	}
	switch e.CollisionStrategy {
	case "suffix-host":
		h := NormalizeLabel(host)
		if h == "" {
			return "", fmt.Errorf("name collision for %s", candidate)
		}
		candidate = base + "-" + h + "." + e.Zone
		if !used[candidate] {
			return candidate, nil
		}
		fallthrough
	case "numeric-suffix":
		for i := 2; i < 1000; i++ {
			n := fmt.Sprintf("%s-%d.%s", base, i, e.Zone)
			if !used[n] {
				return n, nil
			}
		}
		fallthrough
	default:
		return "", fmt.Errorf("name collision for %s", candidate)
	}
}
