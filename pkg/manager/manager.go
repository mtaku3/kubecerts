package manager

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mtaku3/kubecerts/pkg/age"
	"github.com/mtaku3/kubecerts/pkg/ca"
	"github.com/mtaku3/kubecerts/pkg/nix"
	"github.com/mtaku3/kubecerts/pkg/sync"
	"github.com/mtaku3/kubecerts/pkg/types"
)

type Config struct {
	FlakePath  string
	SecretsDir string
	AgeKeyPath string
}

type Manager struct {
	config      *Config
	ageHandler  *age.Handler
	nixParser   *nix.FlakeParser
	caGenerator *ca.Generator
	syncer      *sync.Syncer
}

func New(config *Config) (*Manager, error) {
	ageHandler, err := age.NewHandler(config.AgeKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create age handler: %w", err)
	}

	nixParser := nix.NewFlakeParser(config.FlakePath)
	caGenerator := ca.NewGenerator()
	syncer := sync.NewSyncer(config.SecretsDir, ageHandler)

	return &Manager{
		config:      config,
		ageHandler:  ageHandler,
		nixParser:   nixParser,
		caGenerator: caGenerator,
		syncer:      syncer,
	}, nil
}

func (m *Manager) DiscoverHostsFromFlake(ctx context.Context) ([]types.Host, error) {
	return m.nixParser.DiscoverHosts(ctx)
}

func (m *Manager) GetCertificateStatus(ctx context.Context) (*StatusResult, error) {
	hosts, err := m.DiscoverHostsFromFlake(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover hosts: %w", err)
	}

	result := &StatusResult{
		Timestamp:     time.Now(),
		HostsChecked:  len(hosts),
		OverallHealth: HealthOK,
		HostResults:   make([]HostStatusResult, 0, len(hosts)),
		Summary:       StatusSummary{},
	}

	for _, host := range hosts {
		hostResult, err := m.getHostStatus(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("failed to get status for host %s: %w", host.Name, err)
		}
		
		result.HostResults = append(result.HostResults, *hostResult)
		
		// Update summary
		for _, cert := range hostResult.Certificates {
			switch cert.Status {
			case HealthCritical:
				result.Summary.ExpiredCount++
				result.OverallHealth = HealthCritical
			case HealthWarning:
				if cert.Error == "Certificate file not found" {
					result.Summary.NotFoundCount++
					if result.OverallHealth == HealthOK {
						result.OverallHealth = HealthWarning
					}
				} else {
					result.Summary.WarningCount++
					if result.OverallHealth == HealthOK {
						result.OverallHealth = HealthWarning
					}
				}
			}
		}
	}

	return result, nil
}

func (m *Manager) getHostStatus(ctx context.Context, host types.Host) (*HostStatusResult, error) {
	caTypes := ca.AllCATypes()

	result := &HostStatusResult{
		Host:         host,
		Certificates: make([]CertificateStatusResult, 0, len(caTypes)),
	}

	for _, caType := range caTypes {
		certPath := m.getCertificatePath(host, caType)
		
		certData, err := m.ageHandler.DecryptFile(certPath)
		if err != nil {
			// Check if file doesn't exist
			if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file") {
				result.Certificates = append(result.Certificates, CertificateStatusResult{
					CAType: caType,
					Status: HealthWarning, // Use warning for missing files
					Error:  "Certificate file not found",
				})
			} else {
				// Other errors (decrypt failures, etc)
				result.Certificates = append(result.Certificates, CertificateStatusResult{
					CAType: caType,
					Status: HealthCritical,
					Error:  err.Error(),
				})
			}
			continue
		}

		cert, err := ca.ParseCertificate(certData)
		if err != nil {
			result.Certificates = append(result.Certificates, CertificateStatusResult{
				CAType: caType,
				Status: HealthCritical,
				Error:  err.Error(),
			})
			continue
		}

		status := HealthOK
		if time.Now().After(cert.NotAfter) {
			status = HealthCritical
		}

		// Validate against CSR if available
		csrValid, csrError := m.validateCertificateAgainstCSR(host, caType, cert)
		
		// If CSR validation fails, downgrade status to warning unless already critical
		if csrValid != nil && !*csrValid && status != HealthCritical {
			status = HealthWarning
		}

		result.Certificates = append(result.Certificates, CertificateStatusResult{
			CAType:     caType,
			Status:     status,
			ValidFrom:  cert.NotBefore,
			ValidUntil: cert.NotAfter,
			CSRValid:   csrValid,
			CSRError:   csrError,
		})
	}

	return result, nil
}

// validateCertificateAgainstCSR validates a certificate against its CSR
// Returns (valid, error_message) where valid is nil if CSR not found
// validateCertificateAgainstCSR validates a certificate against an expected CSR
// generated from the host information and CA type
func (m *Manager) validateCertificateAgainstCSR(host types.Host, caType ca.CAType, cert *x509.Certificate) (*bool, string) {
	// Get full host information including AdvertiseIP and Role
	fullHosts, err := m.nixParser.DiscoverFullHosts(context.Background())
	if err != nil {
		return nil, fmt.Sprintf("Failed to get full host info: %v", err)
	}
	
	// Find the matching full host
	var fullHost *nix.FlakeHost
	for _, fh := range fullHosts {
		if fh.Name == host.Name && fh.System == host.System {
			fullHost = &fh
			break
		}
	}
	
	if fullHost == nil {
		return nil, "Host not found in flake discovery"
	}
	
	// Convert to ca.HostInfo
	hostInfo := ca.HostInfo{
		Name:        fullHost.Name,
		System:      fullHost.System,
		AdvertiseIP: fullHost.AdvertiseIP,
		Role:        fullHost.Role.String(),
	}
	
	// Generate expected CSR
	expectedCSR, err := m.caGenerator.GenerateExpectedCSR(caType, hostInfo)
	if err != nil {
		valid := false
		return &valid, fmt.Sprintf("Failed to generate expected CSR: %v", err)
	}
	
	// Validate certificate against expected CSR
	err = ca.ValidateCertificateAgainstExpectedCSR(cert, expectedCSR)
	if err != nil {
		valid := false
		return &valid, fmt.Sprintf("Certificate validation failed: %v", err)
	}
	
	valid := true
	return &valid, ""
}

// getCSRPath returns the path to the CSR file for a given host and CA type
// getCSRPath is deprecated - we now generate expected CSRs from host info
// This method is kept for backward compatibility but should not be used
func (m *Manager) getCSRPath(host types.Host, caType ca.CAType) string {
	// This method is no longer used as we generate expected CSRs dynamically
	return ""
}

func (m *Manager) RenewCertificates(ctx context.Context, caTypes []ca.CAType) (*RenewResult, error) {
	// Get full host information including AdvertiseIP and Role
	fullHosts, err := m.nixParser.DiscoverFullHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover full hosts: %w", err)
	}

	// Convert to types.Host for compatibility
	hosts := make([]types.Host, len(fullHosts))
	for i, fh := range fullHosts {
		hosts[i] = types.Host{
			Name:   fh.Name,
			System: fh.System,
		}
	}

	result := &RenewResult{
		Success:    true,
		Operations: make([]RenewalExecution, 0, len(caTypes)*len(fullHosts)),
		Summary: RenewalResultSummary{
			UpdatedHosts: hosts,
		},
	}

	// Generate new certificates for each host and CA type
	for _, fullHost := range fullHosts {
		// Convert to ca.HostInfo
		hostInfo := ca.HostInfo{
			Name:        fullHost.Name,
			System:      fullHost.System,
			AdvertiseIP: fullHost.AdvertiseIP,
			Role:        fullHost.Role.String(),
		}

		// Convert to types.Host
		host := types.Host{
			Name:   fullHost.Name,
			System: fullHost.System,
		}

		for _, caType := range caTypes {
			// Generate certificate using expected CSR logic
			cert, key, err := m.caGenerator.GenerateCA(caType, hostInfo)
			if err != nil {
				return nil, fmt.Errorf("failed to generate CA %s for host %s: %w", caType, host.Name, err)
			}

			operation := RenewalExecution{
				CAType:     caType,
				ValidFrom:  cert.NotBefore,
				ValidUntil: cert.NotAfter,
			}
			result.Operations = append(result.Operations, operation)

			// Deploy to this specific host
			if err := m.syncer.DeployCertificate(ctx, host, caType, cert, key); err != nil {
				return nil, fmt.Errorf("failed to deploy %s to host %s: %w", caType, host.Name, err)
			}
		}
	}

	result.Summary.CertificatesRenewed = len(caTypes) * len(fullHosts)
	return result, nil
}

func (m *Manager) getCertificatePath(host types.Host, caType ca.CAType) string {
	var fileName string
	switch caType {
	case ca.CATypeKubernetes:
		fileName = "ca.crt.age"
	case ca.CATypeETCD:
		fileName = "etcd/ca.crt.age"
	case ca.CATypeFrontProxy:
		fileName = "front-proxy-ca.crt.age"
	}
	
	return fmt.Sprintf("%s/%s/%s/kubernetes/pki/%s", 
		m.config.SecretsDir, host.System, host.Name, fileName)
}
