package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// HostInfo contains information about a host needed for CSR generation
type HostInfo struct {
	Name        string
	System      string
	AdvertiseIP string
	Role        string
}

type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

func (g *Generator) GenerateCA(caType CAType, hostInfo HostInfo) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate expected CSR to get the proper template
	expectedCSR, err := g.GenerateExpectedCSR(caType, hostInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate expected CSR template: %w", err)
	}

	// Create certificate template based on the expected CSR
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               expectedCSR.Subject,
		DNSNames:              expectedCSR.DNSNames,
		IPAddresses:           expectedCSR.IPAddresses,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0), // 5 years
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return cert, privateKey, nil
}

// GenerateSharedCA generates a CA certificate that is shared across all hosts in the cluster
func (g *Generator) GenerateSharedCA(caType CAType) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Get the expected CSR to use as template for subject
	expectedCSR, err := g.GenerateCAExpectedCSR(caType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate expected CSR: %w", err)
	}

	// Create certificate template for CA using the expected CSR subject
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               expectedCSR.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years for CA
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return cert, privateKey, nil
}

// GenerateCAExpectedCSR generates the expected CSR for CA certificates
// This is used for both CA generation and validation to ensure consistency
func (g *Generator) GenerateCAExpectedCSR(caType CAType) (*x509.CertificateRequest, error) {
	// Create CSR template for CA certificates
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:  []string{"Kubernetes"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
	}

	// Set common name based on CA type
	switch caType {
	case CATypeKubernetes:
		template.Subject.CommonName = "kubernetes-ca"
	case CATypeETCD:
		template.Subject.CommonName = "etcd-ca"
	case CATypeFrontProxy:
		template.Subject.CommonName = "kubernetes-front-proxy-ca"
	default:
		return nil, fmt.Errorf("unknown CA type: %s", caType)
	}

	return template, nil
}



// GenerateExpectedCSR creates the expected CSR for a given CA type and host
// This represents what the CSR should look like for proper certificate validation
func (g *Generator) GenerateExpectedCSR(caType CAType, hostInfo HostInfo) (*x509.CertificateRequest, error) {
	// Create CSR template matching what should be expected
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:  []string{"Kubernetes"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
	}

	// Customize based on CA type
	switch caType {
	case CATypeKubernetes:
		template.Subject.CommonName = "kubernetes-ca"
	case CATypeETCD:
		template.Subject.CommonName = "etcd-ca"
	case CATypeFrontProxy:
		template.Subject.CommonName = "kubernetes-front-proxy-ca"
	default:
		return nil, fmt.Errorf("unknown CA type: %s", caType)
	}

	return template, nil
}

func ParseCertificate(data []byte) (*x509.Certificate, error) {
	// Try to parse as PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM certificate: %w", err)
		}
		return cert, nil
	}

	// Try to parse as DER
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
	}
	return cert, nil
}

// ParseCertificateRequest parses a CSR from PEM or DER encoded data
func ParseCertificateRequest(data []byte) (*x509.CertificateRequest, error) {
	// Try to parse as PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM certificate request: %w", err)
		}
		return csr, nil
	}

	// Try to parse as DER
	csr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate request: %w", err)
	}
	return csr, nil
}

// ValidateCertificateAgainstCSR validates that a certificate was generated from the given CSR
func ValidateCertificateAgainstCSR(cert *x509.Certificate, csr *x509.CertificateRequest) error {
	// Check that the public keys match
	certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not RSA")
	}
	
	csrPubKey, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("CSR public key is not RSA")
	}
	
	if certPubKey.N.Cmp(csrPubKey.N) != 0 || certPubKey.E != csrPubKey.E {
		return fmt.Errorf("certificate and CSR public keys do not match")
	}
	
	// Check that the subject matches (at minimum the common name)
	if cert.Subject.CommonName != csr.Subject.CommonName {
		return fmt.Errorf("certificate and CSR common names do not match: cert=%s, csr=%s", 
			cert.Subject.CommonName, csr.Subject.CommonName)
	}
	
	// Check subject alternative names if present in CSR
	if len(csr.DNSNames) > 0 {
		certDNSNames := make(map[string]bool)
		for _, name := range cert.DNSNames {
			certDNSNames[name] = true
		}
		
		for _, csrDNS := range csr.DNSNames {
			if !certDNSNames[csrDNS] {
				return fmt.Errorf("CSR DNS name %s not found in certificate", csrDNS)
			}
		}
	}
	
	if len(csr.IPAddresses) > 0 {
		certIPs := make(map[string]bool)
		for _, ip := range cert.IPAddresses {
			certIPs[ip.String()] = true
		}
		
		for _, csrIP := range csr.IPAddresses {
			if !certIPs[csrIP.String()] {
				return fmt.Errorf("CSR IP address %s not found in certificate", csrIP.String())
			}
		}
	}
	
	return nil
}

// ValidateCertificateAgainstExpectedCSR validates that a certificate matches what would be expected
// based on the host information and CA type (without requiring an actual stored CSR)
func ValidateCertificateAgainstExpectedCSR(cert *x509.Certificate, expectedCSR *x509.CertificateRequest) error {
	// Check that the subject matches (at minimum the common name)
	if cert.Subject.CommonName != expectedCSR.Subject.CommonName {
		return fmt.Errorf("certificate and expected CSR common names do not match: cert=%s, expected=%s", 
			cert.Subject.CommonName, expectedCSR.Subject.CommonName)
	}
	
	// Check organization
	if len(cert.Subject.Organization) > 0 && len(expectedCSR.Subject.Organization) > 0 {
		if cert.Subject.Organization[0] != expectedCSR.Subject.Organization[0] {
			return fmt.Errorf("certificate and expected CSR organizations do not match: cert=%s, expected=%s",
				cert.Subject.Organization[0], expectedCSR.Subject.Organization[0])
		}
	}
	
	// Check DNS names if expected CSR has them
	if len(expectedCSR.DNSNames) > 0 {
		certDNSNames := make(map[string]bool)
		for _, name := range cert.DNSNames {
			certDNSNames[name] = true
		}
		
		// Check if certificate has all the expected DNS names
		for _, expectedDNS := range expectedCSR.DNSNames {
			if !certDNSNames[expectedDNS] {
				return fmt.Errorf("expected DNS name %s not found in certificate", expectedDNS)
			}
		}
	}
	
	// Check IP addresses if expected CSR has them
	if len(expectedCSR.IPAddresses) > 0 {
		certIPs := make(map[string]bool)
		for _, ip := range cert.IPAddresses {
			certIPs[ip.String()] = true
		}
		
		for _, expectedIP := range expectedCSR.IPAddresses {
			if !certIPs[expectedIP.String()] {
				return fmt.Errorf("expected IP address %s not found in certificate", expectedIP.String())
			}
		}
	}
	
	return nil
}
