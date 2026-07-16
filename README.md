# LabDNS

LabDNS discovers homelab services and safely reconciles readable internal DNS names. The initial release slice is Docker discovery → Pi-hole A records → direct DNS verification → transactional rollback.

LabDNS manages DNS records; it does **not** create reverse-proxy routes or TLS certificates. A Docker bridge address is generally not routable by LAN clients, so LabDNS only proposes host-published or host-network services. It will not overwrite unmanaged records without explicit adoption, and automatic stale deletion is disabled by design. `home.arpa` is the default because `.local` is reserved for multicast DNS.

## Quick start

```sh
go build -o labdns ./cmd/labdns
./labdns init
# Edit labdns.yaml: configure the Pi-hole URL, secret reference, host LAN address, and DNS server.
export LABDNS_PIHOLE_TOKEN='…'
./labdns discover
./labdns plan
./labdns apply
```

Non-interactive runs require an explicit approval:

```sh
labdns apply --config ./labdns.yaml --non-interactive --approve --json
```

Use `labdns tui` for the current read-only dashboard shell. CLI and TUI share the same configuration and application layer.

## Architecture

```text
Docker Engine ──> discovery ──> naming + safe target selection ──> planner
                                                               │
SQLite state <── audit/transaction <── Pi-hole provider <─────┘
                                       │
                         provider check + direct DNS query ───> verification
```

Pi-hole custom-DNS records do not reliably carry arbitrary ownership tags, so LabDNS stores positive ownership in SQLite using provider, zone, name, and type. Matching content alone never means a record is managed.

## Verification

`apply` queries the configured DNS server after the provider mutation. Provider acceptance alone is not success. Configure `verification.direct_dns_server` as `host:port`; system-resolver and split-horizon diagnostics are planned work.

## Development

```sh
go mod tidy
go fmt ./...
go test ./...
go vet ./...
go build ./cmd/labdns
```

The Docker-based Pi-hole end-to-end suite, AdGuard Home adapter, daemon, stale-record handling, advanced record types, backup/export, and full operational TUI are deliberately tracked in `TODO.md` and are not yet represented as supported functionality.
