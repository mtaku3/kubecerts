package manager

import (
	"time"

	"github.com/mtaku3/kubecerts/pkg/ca"
	"github.com/mtaku3/kubecerts/pkg/types"
)

type HealthStatus string

const (
	HealthOK       HealthStatus = "ok"
	HealthWarning  HealthStatus = "warning"
	HealthCritical HealthStatus = "critical"
)

type StatusResult struct {
	Timestamp     time.Time           `json:"timestamp"`
	HostsChecked  int                 `json:"hosts_checked"`
	OverallHealth HealthStatus        `json:"overall_health"`
	HostResults   []HostStatusResult  `json:"host_results"`
	Summary       StatusSummary       `json:"summary"`
}

type HostStatusResult struct {
	Host         types.Host                  `json:"host"`
	Certificates []CertificateStatusResult   `json:"certificates"`
}

type CertificateStatusResult struct {
	CAType      ca.CAType    `json:"ca_type"`
	Status      HealthStatus `json:"status"`
	ValidFrom   time.Time    `json:"valid_from,omitempty"`
	ValidUntil  time.Time    `json:"valid_until,omitempty"`
	Error       string       `json:"error,omitempty"`
	CSRValid    *bool        `json:"csr_valid,omitempty"`    // nil if CSR not found, true/false if validated
	CSRError    string       `json:"csr_error,omitempty"`    // CSR validation error details
}

type StatusSummary struct {
	ExpiredCount     int `json:"expired_count"`
	NotFoundCount    int `json:"not_found_count"`
	WarningCount     int `json:"warning_count"`
}

type RenewResult struct {
	Success    bool                 `json:"success"`
	Operations []RenewalExecution   `json:"operations"`
	Summary    RenewalResultSummary `json:"summary"`
}

type RenewalExecution struct {
	CAType     ca.CAType `json:"ca_type"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
}

type RenewalResultSummary struct {
	CertificatesRenewed int           `json:"certificates_renewed"`
	UpdatedHosts        []types.Host  `json:"updated_hosts"`
}