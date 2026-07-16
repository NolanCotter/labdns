# Architecture

The CLI invokes `internal/app`, which is responsible for discovery, desired-record generation, provider lookup, ownership overlay, planning, transaction execution, and verification. Providers implement `internal/dns.Provider`; no provider name conditionals are permitted outside provider construction. SQLite persists transactions, audit events, and ownership for providers without metadata support.

Apply registers provider rollback input immediately through the transaction journal flow. Any mandatory direct-DNS verification failure invokes provider rollback in reverse operation order.
