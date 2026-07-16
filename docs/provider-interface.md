# Provider interface

Providers expose detection, validation, capabilities, listing, planning, apply, verification, and rollback through `internal/dns.Provider`. The initial implementation is Pi-hole custom DNS records. It supports A records through Pi-hole's supported HTTP endpoint; CNAME/AAAA capability is advertised only where an instance adapter is extended and tested.

AdGuard Home, Technitium, RFC2136, and hosts-file implementations are planned providers, not current supported features.
