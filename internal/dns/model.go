// Package dns defines the provider-neutral domain model and provider contract.
package dns

import (
	"context"
	"net/netip"
	"time"
)

type ServiceSource string

const (
	SourceDocker ServiceSource = "docker"
	SourceManual ServiceSource = "manual"
	SourceStatic ServiceSource = "static"
)

type HostSource string

const (
	HostDocker HostSource = "docker"
	HostManual HostSource = "manual"
	HostStatic HostSource = "static"
)

type RecordType string

const (
	RecordA     RecordType = "A"
	RecordAAAA  RecordType = "AAAA"
	RecordCNAME RecordType = "CNAME"
	RecordPTR   RecordType = "PTR"
	RecordSRV   RecordType = "SRV"
	RecordTXT   RecordType = "TXT"
)

type ChangeType string

const (
	ChangeCreate   ChangeType = "create"
	ChangeUpdate   ChangeType = "update"
	ChangeDelete   ChangeType = "delete"
	ChangeNoChange ChangeType = "no_change"
	ChangeConflict ChangeType = "conflict"
	ChangeBlocked  ChangeType = "blocked"
)

type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckFail CheckStatus = "fail"
	CheckWarn CheckStatus = "warn"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type ServicePort struct {
	Port      uint16 `json:"port"`
	Protocol  string `json:"protocol"`
	Published bool   `json:"published"`
}
type Service struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Source          ServiceSource     `json:"source"`
	HostID          string            `json:"host_id"`
	IPv4Addresses   []netip.Addr      `json:"ipv4_addresses"`
	IPv6Addresses   []netip.Addr      `json:"ipv6_addresses"`
	Ports           []ServicePort     `json:"ports"`
	ContainerID     string            `json:"container_id,omitempty"`
	ComposeProject  string            `json:"compose_project,omitempty"`
	ComposeService  string            `json:"compose_service,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	SuggestedNames  []string          `json:"suggested_names,omitempty"`
	ExistingRecords []DNSRecord       `json:"existing_records,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}
type Host struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	IPv4Addresses []netip.Addr `json:"ipv4_addresses"`
	IPv6Addresses []netip.Addr `json:"ipv6_addresses"`
	MACAddress    string       `json:"mac_address,omitempty"`
	Source        HostSource   `json:"source"`
	LastSeen      time.Time    `json:"last_seen"`
}
type DNSRecord struct {
	ID         string            `json:"id"`
	ProviderID string            `json:"provider_id"`
	Zone       string            `json:"zone"`
	Name       string            `json:"name"`
	Type       RecordType        `json:"type"`
	Value      string            `json:"value"`
	TTL        time.Duration     `json:"ttl"`
	Managed    bool              `json:"managed"`
	SourceID   string            `json:"source_id,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}
type DesiredRecord struct {
	ServiceID string        `json:"service_id"`
	Zone      string        `json:"zone"`
	Name      string        `json:"name"`
	Type      RecordType    `json:"type"`
	Value     string        `json:"value"`
	TTL       time.Duration `json:"ttl"`
}
type Change struct {
	ID          string     `json:"id"`
	Type        ChangeType `json:"type"`
	Record      DNSRecord  `json:"record"`
	Previous    *DNSRecord `json:"previous,omitempty"`
	Reason      string     `json:"reason"`
	Destructive bool       `json:"destructive"`
}
type AppliedChange struct {
	Change            Change    `json:"change"`
	ProviderReference string    `json:"provider_reference,omitempty"`
	AppliedAt         time.Time `json:"applied_at"`
}
type CheckResult struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Target         string        `json:"target"`
	Status         CheckStatus   `json:"status"`
	Severity       Severity      `json:"severity"`
	Evidence       string        `json:"evidence"`
	Recommendation string        `json:"recommendation,omitempty"`
	Duration       time.Duration `json:"duration"`
}
type ProviderInstance struct {
	ID       string            `json:"id"`
	BaseURL  string            `json:"base_url"`
	Version  string            `json:"version,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}
type SecretRef string
type Capabilities struct {
	SupportsA          bool
	SupportsAAAA       bool
	SupportsCNAME      bool
	SupportsPTR        bool
	SupportsSRV        bool
	SupportsTXT        bool
	SupportsZones      bool
	SupportsAtomicEdit bool
	SupportsTags       bool
	SupportsComments   bool
}
type Provider interface {
	ID() string
	DisplayName() string
	Detect(context.Context) ([]ProviderInstance, error)
	Validate(context.Context, ProviderInstance, SecretRef) error
	Capabilities(context.Context, ProviderInstance) (Capabilities, error)
	ListRecords(context.Context, string) ([]DNSRecord, error)
	Plan(context.Context, []DesiredRecord, []DNSRecord) ([]Change, error)
	Apply(context.Context, []Change) ([]AppliedChange, error)
	Verify(context.Context, []DesiredRecord) ([]CheckResult, error)
	Rollback(context.Context, []AppliedChange) error
}
