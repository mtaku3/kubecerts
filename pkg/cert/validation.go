package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/mtaku3/kubecerts/pkg/host"
)

// ValidationResult represents the result of certificate validation
type ValidationResult struct {
	Valid      bool
	Errors     []string
	Warnings   []string
	CertInfo   *CertificateInfo
}

// CertificateInfo contains detailed information about a certificate
type CertificateInfo struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	DNSNames     []string
	IPAddresses  []string
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	IsCA         bool
	DaysLeft     int
}

// ValidateCertificateWithConfig validates a certificate against expected configuration
func ValidateCertificateWithConfig(cert *x509.Certificate, certName string, expectedConfig *CertConfig) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
		CertInfo: extractCertificateInfo(cert),
	}

	// 1. Validate certificate period (expiry)
	if err := ValidateCertPeriod(cert, 0); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Certificate period validation: %v", err))
	}

	// 2. Validate SANs (Subject Alternative Names) - critical validation
	if err := validateSANs(cert, expectedConfig); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("SAN validation failed: %v", err))
	}

	// 3. Validate key usage
	if err := validateKeyUsage(cert, expectedConfig); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Key usage validation failed: %v", err))
		result.Valid = false
	}

	// 4. Validate extended key usage
	if err := validateExtKeyUsage(cert, expectedConfig); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Extended key usage validation failed: %v", err))
		result.Valid = false
	}

	// 5. Validate Subject (CommonName)
	if err := validateSubject(cert, expectedConfig); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Subject validation failed: %v", err))
		result.Valid = false
	}

	// 6. Validate CA constraint
	if cert.IsCA != expectedConfig.IsCA {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("CA constraint mismatch: expected %v, got %v", expectedConfig.IsCA, cert.IsCA))
	}

	return result
}

// ValidateCertificateChain validates that a certificate is properly signed by the given CA
func ValidateCertificateChain(cert *x509.Certificate, caCert *x509.Certificate) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
		CertInfo: extractCertificateInfo(cert),
	}

	// Create certificate pool with CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // Allow any key usage
	}

	_, err := cert.Verify(opts)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Certificate chain validation failed: %v", err))
	}

	return result
}

// ValidateCertPeriod checks if the certificate is valid relative to the current time
func ValidateCertPeriod(cert *x509.Certificate, offset time.Duration) error {
	now := time.Now().Add(offset).UTC()
	
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not valid yet (NotBefore: %v, current time: %v)", 
			cert.NotBefore, now)
	}
	
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (NotAfter: %v, current time: %v)", 
			cert.NotAfter, now)
	}
	
	return nil
}

// ValidateCertificateForHost validates a certificate against host-specific requirements
func ValidateCertificateForHost(cert *x509.Certificate, h host.Host, certName string, expectedConfig *CertConfig) *ValidationResult {
	// First do standard validation
	result := ValidateCertificateWithConfig(cert, certName, expectedConfig)
	
	// Then do host-specific SAN validation
	if err := validateHostSpecificSANs(cert, h); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Host-specific SAN validation failed: %v", err))
	}
	
	return result
}

// validateSANs validates Subject Alternative Names against expected configuration
func validateSANs(cert *x509.Certificate, config *CertConfig) error {
	// Check that all expected DNS names are present
	for _, expectedDNS := range config.DNSNames {
		if err := cert.VerifyHostname(expectedDNS); err != nil {
			return fmt.Errorf("certificate does not contain required DNS name '%s': %v", expectedDNS, err)
		}
	}

	// Check that all expected IP addresses are present
	for _, expectedIPStr := range config.IPAddresses {
		expectedIP := net.ParseIP(expectedIPStr)
		if expectedIP == nil {
			continue // Skip invalid IPs in config
		}
		
		found := false
		for _, certIP := range cert.IPAddresses {
			if certIP.Equal(expectedIP) {
				found = true
				break
			}
		}
		
		if !found {
			return fmt.Errorf("certificate does not contain required IP address '%s'", expectedIPStr)
		}
	}

	return nil
}

// validateHostSpecificSANs validates that certificate works for the specific host
func validateHostSpecificSANs(cert *x509.Certificate, h host.Host) error {
	// Validate hostname
	if err := cert.VerifyHostname(h.Name); err != nil {
		return fmt.Errorf("certificate cannot be used for hostname '%s': %v", h.Name, err)
	}
	
	// Validate advertise IP
	if h.AdvertiseIP != "" {
		advertiseIP := net.ParseIP(h.AdvertiseIP)
		if advertiseIP != nil {
			found := false
			for _, certIP := range cert.IPAddresses {
				if certIP.Equal(advertiseIP) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("certificate does not contain host's advertise IP '%s'", h.AdvertiseIP)
			}
		}
	}
	
	return nil
}

// validateKeyUsage validates certificate key usage against expected configuration
func validateKeyUsage(cert *x509.Certificate, config *CertConfig) error {
	if cert.KeyUsage&config.KeyUsage != config.KeyUsage {
		return fmt.Errorf("certificate key usage %v does not include required usage %v", 
			cert.KeyUsage, config.KeyUsage)
	}
	return nil
}

// validateExtKeyUsage validates certificate extended key usage against expected configuration
func validateExtKeyUsage(cert *x509.Certificate, config *CertConfig) error {
	if len(config.ExtKeyUsage) == 0 {
		return nil // No extended key usage requirements
	}
	
	for _, requiredUsage := range config.ExtKeyUsage {
		found := false
		for _, certUsage := range cert.ExtKeyUsage {
			if certUsage == requiredUsage {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("certificate does not contain required extended key usage %v", requiredUsage)
		}
	}
	
	return nil
}

// extractCertificateInfo extracts detailed information from a certificate
func extractCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	
	var ipStrings []string
	for _, ip := range cert.IPAddresses {
		ipStrings = append(ipStrings, ip.String())
	}
	
	return &CertificateInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DNSNames:     cert.DNSNames,
		IPAddresses:  ipStrings,
		KeyUsage:     cert.KeyUsage,
		ExtKeyUsage:  cert.ExtKeyUsage,
		IsCA:         cert.IsCA,
		DaysLeft:     daysLeft,
	}
}

// validateSubject validates the certificate subject against expected configuration
func validateSubject(cert *x509.Certificate, config *CertConfig) error {
	// Validate CommonName if specified
	if config.CommonName != "" && cert.Subject.CommonName != config.CommonName {
		return fmt.Errorf("certificate CommonName '%s' does not match expected '%s'", 
			cert.Subject.CommonName, config.CommonName)
	}
	
	// Validate Organization if specified
	if len(config.Organization) > 0 {
		if len(cert.Subject.Organization) != len(config.Organization) {
			return fmt.Errorf("certificate Organization count %d does not match expected %d", 
				len(cert.Subject.Organization), len(config.Organization))
		}
		
		for i, expectedOrg := range config.Organization {
			if i >= len(cert.Subject.Organization) || cert.Subject.Organization[i] != expectedOrg {
				return fmt.Errorf("certificate Organization[%d] '%s' does not match expected '%s'", 
					i, cert.Subject.Organization[i], expectedOrg)
			}
		}
	}
	
	return nil
}

// ValidateCAKeyPair validates that a CA certificate and private key match
func ValidateCAKeyPair(cert *x509.Certificate, key *rsa.PrivateKey) error {
	// Check that the public key in the certificate matches the private key
	certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain an RSA public key")
	}
	
	if !certPubKey.Equal(&key.PublicKey) {
		return fmt.Errorf("certificate and private key do not match")
	}
	
	return nil
}
