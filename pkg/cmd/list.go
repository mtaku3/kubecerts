package cmd

import (
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mtaku3/kubecerts/pkg/cert"
	"github.com/mtaku3/kubecerts/pkg/host"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// CertificateInfo holds information about a certificate
type CertificateInfo struct {
	Host         string
	Role         string
	CertificateFile string
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	DaysLeft     int
	Status       string
}

// NewListCommand creates the list command
func NewListCommand() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all certificates with expiry information",
		Long:  "List all certificates in the cluster with their expiry dates and status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm, err := NewCertManager()
			if err != nil {
				return err
			}

			return cm.ListCertificates(verbose)
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed certificate information")

	return cmd
}

// getCertificatePriority returns a priority number for sorting certificates
// Lower numbers appear first
func getCertificatePriority(certFile string) int {
	switch {
	// CA certificates first (priority 1)
	case strings.HasSuffix(certFile, "ca.crt"):
		return 1
	// Service certificates (priority 2)
	case certFile == "apiserver.crt":
		return 2
	case certFile == "apiserver-kubelet-client.crt":
		return 3
	case certFile == "apiserver-etcd-client.crt":
		return 4
	case certFile == "front-proxy-client.crt":
		return 5
	// Etcd certificates (priority 3)
	case strings.HasPrefix(certFile, "etcd/") && !strings.HasSuffix(certFile, "ca.crt"):
		switch certFile {
		case "etcd/server.crt":
			return 6
		case "etcd/peer.crt":
			return 7
		case "etcd/healthcheck-client.crt":
			return 8
		default:
			return 9
		}
	// Client certificates (priority 4)
	case certFile == "kubelet-client.crt":
		return 10
	case certFile == "controller-manager-client.crt":
		return 11
	case certFile == "scheduler-client.crt":
		return 12
	// Everything else
	default:
		return 99
	}
}

// ListCertificates lists all certificates with their status
func (cm *CertManager) ListCertificates(verbose bool) error {
	var allCerts []CertificateInfo
	now := time.Now()

	for _, h := range cm.hosts {
		// Get certificates for this host
		certs := cm.getCertificatesForHost(h, now)
		allCerts = append(allCerts, certs...)
	}

	// Sort by host first, then by certificate type for better readability
	sort.Slice(allCerts, func(i, j int) bool {
		// First sort by host name
		if allCerts[i].Host != allCerts[j].Host {
			return allCerts[i].Host < allCerts[j].Host
		}
		
		// Then sort by certificate priority (CAs first, then service certs)
		iPriority := getCertificatePriority(allCerts[i].CertificateFile)
		jPriority := getCertificatePriority(allCerts[j].CertificateFile)
		if iPriority != jPriority {
			return iPriority < jPriority
		}
		
		// Finally sort by certificate name
		return allCerts[i].CertificateFile < allCerts[j].CertificateFile
	})

	// Display certificates
	if verbose {
		cm.displayVerboseCertificates(allCerts)
	} else {
		cm.displayConciseCertificates(allCerts)
	}

	return nil
}

func (cm *CertManager) getCertificatesForHost(h host.Host, now time.Time) []CertificateInfo {
	var certs []CertificateInfo

	// Certificate files to check based on role
	certFiles := []string{"kubelet-client.crt"}
	
	// Add CA certificates (all hosts have these)
	certFiles = append(certFiles, "ca.crt", "front-proxy-ca.crt", "etcd/ca.crt")

	if h.Role == host.Master {
		certFiles = append(certFiles,
			"apiserver.crt",
			"apiserver-kubelet-client.crt",
			"apiserver-etcd-client.crt", 
			"front-proxy-client.crt",
			"etcd/server.crt",
			"etcd/peer.crt",
			"etcd/healthcheck-client.crt",
			"controller-manager-client.crt",
			"scheduler-client.crt",
		)
	}

	for _, certFile := range certFiles {
		if certInfo := cm.getCertificateInfo(h, certFile, now); certInfo != nil {
			certs = append(certs, *certInfo)
		} else {
			// Add missing certificate entry
			certs = append(certs, CertificateInfo{
				Host:            h.Name,
				Role:            h.Role.String(),
				CertificateFile: certFile,
				Subject:         "N/A",
				Issuer:          "N/A",
				DaysLeft:        0,
				Status:          "MISSING",
			})
		}
	}

	return certs
}

func (cm *CertManager) getCertificateInfo(h host.Host, certFile string, now time.Time) *CertificateInfo {
	if !cm.storage.CertificateExists(h, certFile) {
		return nil
	}

	certPEM, err := cm.storage.LoadCertificate(h, certFile)
	if err != nil {
		logrus.Warnf("Failed to load %s for %s: %v", certFile, h.Name, err)
		return nil
	}

	certificate, err := cert.ParseCertificateFromPEM(certPEM)
	if err != nil {
		logrus.Warnf("Failed to parse %s for %s: %v", certFile, h.Name, err)
		return nil
	}

	daysLeft := int(certificate.NotAfter.Sub(now).Hours() / 24)
	
	// Perform comprehensive validation to determine status
	status := cm.getComprehensiveStatus(h, certFile, certificate, daysLeft)

	return &CertificateInfo{
		Host:         h.Name,
		Role:         h.Role.String(),
		CertificateFile: certFile,
		Subject:      certificate.Subject.CommonName,
		Issuer:       certificate.Issuer.CommonName,
		NotBefore:    certificate.NotBefore,
		NotAfter:     certificate.NotAfter,
		DaysLeft:     daysLeft,
		Status:       status,
	}
}

// getComprehensiveStatus performs comprehensive validation and returns a status string
func (cm *CertManager) getComprehensiveStatus(h host.Host, certFile string, certificate *x509.Certificate, daysLeft int) string {
	// Check expiry status first
	if daysLeft < 0 {
		return "EXPIRED"
	}
	
	// Get expected configuration for this certificate type
	expectedConfig := cm.getExpectedConfigForCert(h, certFile)
	if expectedConfig == nil {
		// If we can't determine expected config, fall back to expiry-only status
		if daysLeft < 30 {
			return "WARNING"
		} else if daysLeft < 90 {
			return "RENEWAL_SOON"
		}
		return "OK"
	}
	
	// Load CA certificate for chain validation if needed
	var caCert *cert.CertificateBundle = nil
	caFile := cm.getCAFileForCert(certFile)
	if caFile != "" && cm.storage.CertificateExists(h, caFile) {
		caCertPEM, err := cm.storage.LoadCertificate(h, caFile)
		if err == nil {
			caCertX509, err := cert.ParseCertificateFromPEM(caCertPEM)
			if err == nil {
				caCert = &cert.CertificateBundle{Certificate: caCertX509}
			}
		}
	}
	
	// Perform comprehensive validation
	result := cert.ValidateCertificateWithConfig(certificate, certFile, expectedConfig)
	
	// Perform host-specific validation for service certificates
	if expectedConfig.DNSNames != nil || expectedConfig.IPAddresses != nil {
		hostResult := cert.ValidateCertificateForHost(certificate, h, certFile, expectedConfig)
		if !hostResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, hostResult.Errors...)
		}
	}
	
	// Perform certificate chain validation if CA is available
	if caCert != nil && caCert.Certificate != nil {
		chainResult := cert.ValidateCertificateChain(certificate, caCert.Certificate)
		if !chainResult.Valid {
			result.Valid = false
		}
	}
	
	// Determine final status
	if !result.Valid {
		return "INVALID"
	}
	
	// If valid but expiry warnings
	if daysLeft < 30 {
		return "WARNING"
	} else if daysLeft < 90 {
		return "RENEWAL_SOON"
	}
	
	return "OK"
}

// getExpectedConfigForCert returns the expected configuration for a certificate type
func (cm *CertManager) getExpectedConfigForCert(h host.Host, certFile string) *cert.CertConfig {
	switch certFile {
	case "ca.crt":
		return cert.NewKubernetesCAConfig()
	case "front-proxy-ca.crt":
		return cert.NewFrontProxyCAConfig()
	case "etcd/ca.crt":
		return cert.NewEtcdCAConfig()
	case "apiserver.crt":
		return cert.NewAPIServerConfig(h.Name, h.AdvertiseIP)
	case "apiserver-kubelet-client.crt":
		return cert.NewAPIServerKubeletClientConfig()
	case "apiserver-etcd-client.crt":
		return cert.NewAPIServerEtcdClientConfig()
	case "front-proxy-client.crt":
		return cert.NewFrontProxyClientConfig()
	case "etcd/server.crt":
		return cert.NewEtcdServerConfig(h.Name, h.AdvertiseIP)
	case "etcd/peer.crt":
		return cert.NewEtcdPeerConfig(h.Name, h.AdvertiseIP)
	case "etcd/healthcheck-client.crt":
		return cert.NewEtcdHealthcheckClientConfig()
	case "kubelet-client.crt":
		return cert.NewKubeletClientConfig(h.Name)
	case "controller-manager-client.crt":
		return cert.NewControllerManagerClientConfig()
	case "scheduler-client.crt":
		return cert.NewSchedulerClientConfig()
	default:
		return nil
	}
}

// getCAFileForCert returns the CA file for a given certificate
func (cm *CertManager) getCAFileForCert(certFile string) string {
	switch certFile {
	case "apiserver.crt", "apiserver-kubelet-client.crt", "apiserver-etcd-client.crt", "kubelet-client.crt", "controller-manager-client.crt", "scheduler-client.crt":
		return "ca.crt"
	case "front-proxy-client.crt":
		return "front-proxy-ca.crt"
	case "etcd/server.crt", "etcd/peer.crt", "etcd/healthcheck-client.crt":
		return "etcd/ca.crt"
	default:
		return "" // CA certificates don't have parent CAs to validate against
	}
}

func (cm *CertManager) displayConciseCertificates(certs []CertificateInfo) {
	// Calculate maximum widths for each column
	hostWidth := len("HOST")
	roleWidth := len("ROLE")
	certWidth := len("CERTIFICATE")
	subjectWidth := len("SUBJECT")
	daysWidth := len("DAYS LEFT")
	statusWidth := len("STATUS")

	for _, cert := range certs {
		if len(cert.Host) > hostWidth {
			hostWidth = len(cert.Host)
		}
		if len(cert.Role) > roleWidth {
			roleWidth = len(cert.Role)
		}
		if len(cert.CertificateFile) > certWidth {
			certWidth = len(cert.CertificateFile)
		}
		if len(cert.Subject) > subjectWidth {
			subjectWidth = len(cert.Subject)
		}
		if len(fmt.Sprintf("%d", cert.DaysLeft)) > daysWidth {
			daysWidth = len(fmt.Sprintf("%d", cert.DaysLeft))
		}
		if len(cert.Status) > statusWidth {
			statusWidth = len(cert.Status)
		}
	}

	// Add padding
	hostWidth += 2
	roleWidth += 2
	certWidth += 2
	subjectWidth += 2
	daysWidth += 2
	statusWidth += 2

	// Print header
	headerFormat := fmt.Sprintf("%%-%ds%%-%ds%%-%ds%%-%ds%%-%ds%%s\n", 
		hostWidth, roleWidth, certWidth, subjectWidth, daysWidth)
	fmt.Printf(headerFormat, "HOST", "ROLE", "CERTIFICATE", "SUBJECT", "DAYS LEFT", "STATUS")
	
	totalWidth := hostWidth + roleWidth + certWidth + subjectWidth + daysWidth + statusWidth
	fmt.Printf("%s\n", strings.Repeat("-", totalWidth))

	// Print rows
	rowFormat := fmt.Sprintf("%%-%ds%%-%ds%%-%ds%%-%ds%%%dd  %%s%%s%%s\n", 
		hostWidth, roleWidth, certWidth, subjectWidth, daysWidth-2)

	for _, cert := range certs {
		statusColor := ""
		switch cert.Status {
		case "EXPIRED":
			statusColor = "\033[31m" // Red
		case "WARNING":
			statusColor = "\033[33m" // Yellow
		case "RENEWAL_SOON":
			statusColor = "\033[33m" // Yellow
		case "MISSING":
			statusColor = "\033[31m" // Red
		default:
			statusColor = "\033[32m" // Green
		}
		resetColor := "\033[0m"

		fmt.Printf(rowFormat,
			cert.Host,
			cert.Role,
			cert.CertificateFile,
			cert.Subject,
			cert.DaysLeft,
			statusColor,
			cert.Status,
			resetColor,
		)
	}

	// Summary
	expired := 0
	warning := 0
	missing := 0
	ok := 0
	for _, cert := range certs {
		switch cert.Status {
		case "EXPIRED":
			expired++
		case "WARNING", "RENEWAL_SOON":
			warning++
		case "MISSING":
			missing++
		default:
			ok++
		}
	}

	fmt.Printf("\nSummary: %d OK, %d WARNING, %d EXPIRED, %d MISSING\n", ok, warning, expired, missing)
}

func (cm *CertManager) displayVerboseCertificates(certs []CertificateInfo) {
	for _, cert := range certs {
		fmt.Printf("Certificate: %s on %s (%s)\n", cert.CertificateFile, cert.Host, cert.Role)
		fmt.Printf("  Subject: %s\n", cert.Subject)
		fmt.Printf("  Issuer: %s\n", cert.Issuer)
		fmt.Printf("  Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Days Left: %d\n", cert.DaysLeft)
		
		statusColor := ""
		switch cert.Status {
		case "EXPIRED":
			statusColor = "\033[31m"
		case "WARNING", "RENEWAL_SOON":
			statusColor = "\033[33m"
		case "MISSING":
			statusColor = "\033[31m"
		default:
			statusColor = "\033[32m"
		}
		
		fmt.Printf("  Status: %s%s\033[0m\n", statusColor, cert.Status)
		fmt.Println()
	}
}