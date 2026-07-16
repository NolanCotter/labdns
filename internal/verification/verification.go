package verification

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/labdns/labdns/internal/dns"
	mdns "github.com/miekg/dns"
	"strings"
	"time"
)

func Direct(ctx context.Context, server string, desired []dns.DesiredRecord, timeout time.Duration) []dns.CheckResult {
	out := make([]dns.CheckResult, 0, len(desired))
	for _, d := range desired {
		start := time.Now()
		r := dns.CheckResult{ID: uuid.NewString(), Name: d.Name, Target: d.Value, Status: dns.CheckFail, Severity: dns.SeverityCritical, Duration: 0}
		if server == "" {
			r.Status = dns.CheckWarn
			r.Severity = dns.SeverityWarning
			r.Evidence = "direct DNS server is not configured"
			out = append(out, r)
			continue
		}
		q := new(mdns.Msg)
		q.SetQuestion(mdns.Fqdn(d.Name), typeCode(d.Type))
		client := mdns.Client{Timeout: timeout}
		resp, _, e := client.ExchangeContext(ctx, q, server)
		r.Duration = time.Since(start)
		if e != nil {
			r.Evidence = "DNS query failed: " + e.Error()
			out = append(out, r)
			continue
		}
		if resp.Rcode != mdns.RcodeSuccess {
			r.Evidence = fmt.Sprintf("DNS response code %s", mdns.RcodeToString[resp.Rcode])
			out = append(out, r)
			continue
		}
		for _, a := range resp.Answer {
			if strings.Contains(a.String(), d.Value) {
				r.Status = dns.CheckPass
				r.Evidence = "direct DNS server returned expected answer"
				break
			}
		}
		if r.Status != dns.CheckPass {
			r.Evidence = "direct DNS server did not return expected answer"
		}
		out = append(out, r)
	}
	return out
}
func typeCode(t dns.RecordType) uint16 {
	switch t {
	case dns.RecordAAAA:
		return mdns.TypeAAAA
	case dns.RecordCNAME:
		return mdns.TypeCNAME
	case dns.RecordPTR:
		return mdns.TypePTR
	case dns.RecordSRV:
		return mdns.TypeSRV
	case dns.RecordTXT:
		return mdns.TypeTXT
	default:
		return mdns.TypeA
	}
}
