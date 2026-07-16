# LabDNS delivery plan

- [x] Foundation: Go module, typed config/domain models, SQLite migrations, audit journal, CLI and TUI shell.
- [x] First vertical slice: Docker discovery, safe LAN target selection, naming, Pi-hole records, planning, transactional apply, direct DNS verification and rollback.
- [ ] AdGuard Home complete adapter and end-to-end Docker test.
- [ ] Daemon, stale-record lifecycle, doctor and repair.
- [ ] Technitium, RFC2136 and hosts-file adapters.
- [ ] Advanced records (AAAA/PTR/SRV/TXT), full TUI, backup/export and release hardening.

## Environment blockers

- Go is not installed in the current development environment, so `go fmt`, `go test`, `go vet`, and builds cannot yet run. Install Go 1.23+ and execute the verification commands in README.md.
