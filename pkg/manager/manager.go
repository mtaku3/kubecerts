package manager

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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

	// Check for certificate consistency issues
	result.Summary.ConsistencyIssues = detectConsistencyIssues(result.HostResults)
	
	// If consistency issues found, ensure overall health reflects this
	if len(result.Summary.ConsistencyIssues) > 0 && result.OverallHealth == HealthOK {
		result.OverallHealth = HealthWarning
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
			CAType:      caType,
			Status:      status,
			ValidFrom:   cert.NotBefore,
			ValidUntil:  cert.NotAfter,
			CSRValid:    csrValid,
			CSRError:    csrError,
			Fingerprint: computeCertificateFingerprint(certData),
		})
	}

	return result, nil
}

// validateCertificateAgainstCSR validates a certificate against its corresponding CSR if available
// validateCertificateAgainstCSR validates a certificate against its expected CSR
func (m *Manager) validateCertificateAgainstCSR(host types.Host, caType ca.CAType, cert *x509.Certificate) (*bool, string) {
	// For CA certificates, generate the expected CSR on-the-fly
	expectedCSR, err := m.caGenerator.GenerateCAExpectedCSR(caType)
	if err != nil {
		boolFalse := false
		return &boolFalse, fmt.Sprintf("failed to generate expected CSR: %v", err)
	}
	
	// Validate the certificate against the expected CSR
	err = ca.ValidateCertificateAgainstExpectedCSR(cert, expectedCSR)
	if err != nil {
		boolFalse := false
		return &boolFalse, fmt.Sprintf("validation failed: %v", err)
	}
	
	boolTrue := true
	return &boolTrue, ""
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

// computeCertificateFingerprint computes SHA256 fingerprint of certificate data for consistency checking
func computeCertificateFingerprint(certData []byte) string {
	hash := sha256.Sum256(certData)
	return hex.EncodeToString(hash[:])
}

// detectConsistencyIssues analyzes certificate fingerprints across hosts to find inconsistencies
func detectConsistencyIssues(hostResults []HostStatusResult) []ConsistencyIssue {
	var issues []ConsistencyIssue
	
	// Group certificates by CA type
	certsByType := make(map[ca.CAType]map[string][]string) // CA Type -> Fingerprint -> Host names
	
	for _, hostResult := range hostResults {
		for _, cert := range hostResult.Certificates {
			// Only consider certificates that were successfully loaded (have fingerprints)
			if cert.Fingerprint == "" || cert.Status == HealthCritical {
				continue
			}
			
			if certsByType[cert.CAType] == nil {
				certsByType[cert.CAType] = make(map[string][]string)
			}
			
			certsByType[cert.CAType][cert.Fingerprint] = append(
				certsByType[cert.CAType][cert.Fingerprint], 
				hostResult.Host.Name,
			)
		}
	}
	
	// Check for inconsistencies (multiple fingerprints for same CA type)
	for caType, fingerprints := range certsByType {
		if len(fingerprints) > 1 {
			// Multiple different certificates exist for this CA type
			var hostGroups []string
			for fingerprint, hosts := range fingerprints {
				hostGroups = append(hostGroups, fmt.Sprintf("%s (hosts: %s)", 
					fingerprint[:16]+"...", strings.Join(hosts, ", ")))
			}
			
			issues = append(issues, ConsistencyIssue{
				CAType:      caType,
				Description: fmt.Sprintf("Different certificates found across hosts: %s", strings.Join(hostGroups, "; ")),
				Hosts:       getAllHostsForCAType(fingerprints),
			})
		}
	}
	
	return issues
}

// getAllHostsForCAType extracts all host names from fingerprint groups
func getAllHostsForCAType(fingerprints map[string][]string) []string {
	var allHosts []string
	for _, hosts := range fingerprints {
		allHosts = append(allHosts, hosts...)
	}
	return allHosts
}

// RenewCertificates generates new CA certificates and deploys them to all hosts
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
		Operations: make([]RenewalExecution, 0, len(caTypes)),
		Summary: RenewalResultSummary{
			UpdatedHosts: hosts,
		},
	}

	// Generate certificates once per CA type (not per host)
	// CA certificates should be identical across all hosts in a cluster
	generatedCAs := make(map[ca.CAType]struct {
		cert *x509.Certificate
		key  *rsa.PrivateKey
	})

	for _, caType := range caTypes {
		// Generate CA certificate once (shared across all hosts)
		cert, key, err := m.caGenerator.GenerateSharedCA(caType)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA %s: %w", caType, err)
		}

		generatedCAs[caType] = struct {
			cert *x509.Certificate
			key  *rsa.PrivateKey
		}{cert: cert, key: key}

		operation := RenewalExecution{
			CAType:     caType,
			ValidFrom:  cert.NotBefore,
			ValidUntil: cert.NotAfter,
		}
		result.Operations = append(result.Operations, operation)
	}

	// Deploy the same CA certificates to all hosts
	for _, host := range hosts {
		for _, caType := range caTypes {
			caData := generatedCAs[caType]
			
			// Deploy the shared CA certificate to this host
			if err := m.syncer.DeployCertificate(ctx, host, caType, caData.cert, caData.key); err != nil {
				return nil, fmt.Errorf("failed to deploy %s to host %s: %w", caType, host.Name, err)
			}
		}
	}

	result.Summary.CertificatesRenewed = len(caTypes) * len(hosts)
	return result, nil
}
