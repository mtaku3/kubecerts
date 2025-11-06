package cmd

import (
	"fmt"
	"time"

	"github.com/mtaku3/kubecerts/pkg/cert"
	"github.com/mtaku3/kubecerts/pkg/host"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// NewCheckCommand creates the check command
func NewCheckCommand() *cobra.Command {
	var expiryOnly bool
	
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check certificate validity",
		Long:  "Check certificates for expiry, SAN validation, key usage, and certificate chain validation",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm, err := NewCertManager()
			if err != nil {
				return err
			}

			if expiryOnly {
				return cm.CheckCertificates()
			}
			return cm.CheckCertificatesComprehensive()
		},
	}
	
	cmd.Flags().BoolVar(&expiryOnly, "expiry-only", false, "Only check certificate expiry (skip comprehensive validation)")
	
	return cmd
}

// CheckCertificates checks all certificates for expiry
func (cm *CertManager) CheckCertificates() error {
	now := time.Now()
	warningThreshold := 30 * 24 * time.Hour // 30 days

	logrus.Info("Checking certificate expiry...")

	for _, h := range cm.hosts {
		logrus.Infof("Checking certificates for host %s", h.Name)

		// Check CA certificates
		if err := cm.checkCertificateExpiry(h, "ca.crt", now, warningThreshold); err != nil {
			logrus.Warnf("Failed to check CA certificate for %s: %v", h.Name, err)
		}

		if err := cm.checkCertificateExpiry(h, "front-proxy-ca.crt", now, warningThreshold); err != nil {
			logrus.Warnf("Failed to check front-proxy CA certificate for %s: %v", h.Name, err)
		}

		if err := cm.checkCertificateExpiry(h, "etcd/ca.crt", now, warningThreshold); err != nil {
			logrus.Warnf("Failed to check etcd CA certificate for %s: %v", h.Name, err)
		}

		// Check service certificates for master nodes
		if h.Role == host.Master {
			certificates := []string{
				"apiserver.crt",
				"apiserver-kubelet-client.crt",
				"apiserver-etcd-client.crt",
				"front-proxy-client.crt",
				"etcd/server.crt",
				"etcd/peer.crt",
				"etcd/healthcheck-client.crt",
			}

			for _, certFile := range certificates {
				if err := cm.checkCertificateExpiry(h, certFile, now, warningThreshold); err != nil {
					logrus.Warnf("Failed to check %s for %s: %v", certFile, h.Name, err)
				}
			}
		}

		// Check kubelet certificate
		if err := cm.checkCertificateExpiry(h, "kubelet-client.crt", now, warningThreshold); err != nil {
			logrus.Warnf("Failed to check kubelet certificate for %s: %v", h.Name, err)
		}
	}

	return nil
}

func (cm *CertManager) checkCertificateExpiry(h host.Host, certFile string, now time.Time, warningThreshold time.Duration) error {
	if !cm.storage.CertificateExists(h, certFile) {
		logrus.Warnf("Certificate %s does not exist for host %s", certFile, h.Name)
		return nil
	}

	certPEM, err := cm.storage.LoadCertificate(h, certFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	certificate, err := cert.ParseCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	timeUntilExpiry := certificate.NotAfter.Sub(now)

	if timeUntilExpiry < 0 {
		logrus.Errorf("EXPIRED: %s for %s expired on %s", certFile, h.Name, certificate.NotAfter.Format("2006-01-02 15:04:05"))
	} else if timeUntilExpiry < warningThreshold {
		logrus.Warnf("WARNING: %s for %s expires in %d days on %s", 
			certFile, h.Name, int(timeUntilExpiry.Hours()/24), certificate.NotAfter.Format("2006-01-02 15:04:05"))
	} else {
		logrus.Infof("OK: %s for %s expires in %d days on %s", 
			certFile, h.Name, int(timeUntilExpiry.Hours()/24), certificate.NotAfter.Format("2006-01-02 15:04:05"))
	}

	return nil
}

// CheckCertificatesComprehensive performs comprehensive validation
func (cm *CertManager) CheckCertificatesComprehensive() error {
	logrus.Info("Performing comprehensive certificate validation...")
	
	hasErrors := false
	
	for _, h := range cm.hosts {
		logrus.Infof("Validating certificates for host %s (%s)", h.Name, h.Role)
		
		// Validate CA certificates first
		caValidation := cm.validateCACertificates(h)
		if !caValidation {
			hasErrors = true
		}
		
		// Validate service certificates for master nodes
		if h.Role == host.Master {
			serviceValidation := cm.validateServiceCertificates(h)
			if !serviceValidation {
				hasErrors = true
			}
		}
		
		// Validate kubelet certificate
		kubeletValidation := cm.validateKubeletCertificate(h)
		if !kubeletValidation {
			hasErrors = true
		}
	}
	
	if hasErrors {
		logrus.Error("Certificate validation completed with errors")
		return fmt.Errorf("certificate validation failed")
	}
	
	logrus.Info("All certificates passed comprehensive validation")
	return nil
}

// validateCACertificates validates CA certificates for a host
func (cm *CertManager) validateCACertificates(h host.Host) bool {
	caCerts := []struct {
		file   string
		config *cert.CertConfig
	}{
		{"ca.crt", cert.NewKubernetesCAConfig()},
		{"front-proxy-ca.crt", cert.NewFrontProxyCAConfig()},
		{"etcd/ca.crt", cert.NewEtcdCAConfig()},
	}
	
	allValid := true
	
	for _, ca := range caCerts {
		if !cm.storage.CertificateExists(h, ca.file) {
			logrus.Warnf("CA certificate %s missing for host %s", ca.file, h.Name)
			continue
		}
		
		result := cm.validateSingleCertificate(h, ca.file, ca.config, nil)
		if !result.Valid {
			allValid = false
			logrus.Errorf("CA certificate %s validation failed for host %s:", ca.file, h.Name)
			for _, err := range result.Errors {
				logrus.Errorf("  - %s", err)
			}
		} else {
			logrus.Infof("CA certificate %s is valid for host %s", ca.file, h.Name)
		}
		
		// Print warnings if any
		for _, warning := range result.Warnings {
			logrus.Warnf("  - %s", warning)
		}
	}
	
	return allValid
}

// validateServiceCertificates validates service certificates for a master host
func (cm *CertManager) validateServiceCertificates(h host.Host) bool {
	serviceCerts := []struct {
		file   string
		config *cert.CertConfig
		caFile string
	}{
		{"apiserver.crt", cert.NewAPIServerConfig(h.Name, h.AdvertiseIP), "ca.crt"},
		{"apiserver-kubelet-client.crt", cert.NewAPIServerKubeletClientConfig(), "ca.crt"},
		{"apiserver-etcd-client.crt", cert.NewAPIServerEtcdClientConfig(), "ca.crt"},
		{"front-proxy-client.crt", cert.NewFrontProxyClientConfig(), "front-proxy-ca.crt"},
		{"etcd/server.crt", cert.NewEtcdServerConfig(h.Name, h.AdvertiseIP), "etcd/ca.crt"},
		{"etcd/peer.crt", cert.NewEtcdPeerConfig(h.Name, h.AdvertiseIP), "etcd/ca.crt"},
		{"etcd/healthcheck-client.crt", cert.NewEtcdHealthcheckClientConfig(), "etcd/ca.crt"},
	}
	
	allValid := true
	
	for _, serviceCert := range serviceCerts {
		if !cm.storage.CertificateExists(h, serviceCert.file) {
			logrus.Warnf("Service certificate %s missing for host %s", serviceCert.file, h.Name)
			continue
		}
		
		// Load CA certificate for chain validation
		var caCert *cert.CertificateBundle = nil
		if cm.storage.CertificateExists(h, serviceCert.caFile) {
			caCertPEM, err := cm.storage.LoadCertificate(h, serviceCert.caFile)
			if err == nil {
				caCertX509, err := cert.ParseCertificateFromPEM(caCertPEM)
				if err == nil {
					caCert = &cert.CertificateBundle{Certificate: caCertX509}
				}
			}
		}
		
		result := cm.validateSingleCertificate(h, serviceCert.file, serviceCert.config, caCert)
		if !result.Valid {
			allValid = false
			logrus.Errorf("Service certificate %s validation failed for host %s:", serviceCert.file, h.Name)
			for _, err := range result.Errors {
				logrus.Errorf("  - %s", err)
			}
		} else {
			logrus.Infof("Service certificate %s is valid for host %s", serviceCert.file, h.Name)
		}
		
		// Print warnings if any
		for _, warning := range result.Warnings {
			logrus.Warnf("  - %s", warning)
		}
	}
	
	return allValid
}

// validateKubeletCertificate validates kubelet client certificate
func (cm *CertManager) validateKubeletCertificate(h host.Host) bool {
	certFile := "kubelet-client.crt"
	
	if !cm.storage.CertificateExists(h, certFile) {
		logrus.Warnf("Kubelet certificate %s missing for host %s", certFile, h.Name)
		return true // Not critical if missing
	}
	
	// Load CA certificate for chain validation
	var caCert *cert.CertificateBundle = nil
	if cm.storage.CertificateExists(h, "ca.crt") {
		caCertPEM, err := cm.storage.LoadCertificate(h, "ca.crt")
		if err == nil {
			caCertX509, err := cert.ParseCertificateFromPEM(caCertPEM)
			if err == nil {
				caCert = &cert.CertificateBundle{Certificate: caCertX509}
			}
		}
	}
	
	config := cert.NewKubeletClientConfig(h.Name)
	result := cm.validateSingleCertificate(h, certFile, config, caCert)
	
	if !result.Valid {
		logrus.Errorf("Kubelet certificate validation failed for host %s:", h.Name)
		for _, err := range result.Errors {
			logrus.Errorf("  - %s", err)
		}
		return false
	}
	
	logrus.Infof("Kubelet certificate is valid for host %s", h.Name)
	
	// Print warnings if any
	for _, warning := range result.Warnings {
		logrus.Warnf("  - %s", warning)
	}
	
	return true
}

// validateSingleCertificate performs comprehensive validation on a single certificate
func (cm *CertManager) validateSingleCertificate(h host.Host, certFile string, expectedConfig *cert.CertConfig, caCert *cert.CertificateBundle) *cert.ValidationResult {
	// Load certificate
	certPEM, err := cm.storage.LoadCertificate(h, certFile)
	if err != nil {
		return &cert.ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("failed to load certificate: %v", err)},
		}
	}
	
	certificate, err := cert.ParseCertificateFromPEM(certPEM)
	if err != nil {
		return &cert.ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("failed to parse certificate: %v", err)},
		}
	}
	
	// Perform configuration validation
	result := cert.ValidateCertificateWithConfig(certificate, certFile, expectedConfig)
	
	// Perform host-specific validation for service certificates
	if expectedConfig.DNSNames != nil || expectedConfig.IPAddresses != nil {
		hostResult := cert.ValidateCertificateForHost(certificate, h, certFile, expectedConfig)
		if !hostResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, hostResult.Errors...)
		}
		result.Warnings = append(result.Warnings, hostResult.Warnings...)
	}
	
	// Perform certificate chain validation if CA is available
	if caCert != nil && caCert.Certificate != nil {
		chainResult := cert.ValidateCertificateChain(certificate, caCert.Certificate)
		if !chainResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, chainResult.Errors...)
		}
		result.Warnings = append(result.Warnings, chainResult.Warnings...)
	}
	
	return result
}