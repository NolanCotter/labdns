# Security model

LabDNS validates zones and target addresses before planning. It rejects loopback, unspecified, multicast, and link-local configured target addresses. Network discovery is Docker-only in the current slice; subnet scanning is not implemented and is never implicit. Secrets are referenced rather than stored in YAML. The current development secret resolver supports `env:NAME`; keyring and encrypted-file storage remain planned.

Providers use bounded HTTP clients. LabDNS does not log secret values. Record updates are blocked whenever the existing record lacks positive LabDNS ownership.
