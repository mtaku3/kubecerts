package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateRSAKey generates a new RSA private key
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// GenerateServiceAccountKeyPair generates RSA key pair for service account tokens
func GenerateServiceAccountKeyPair() (*CertificateBundle, error) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	return &CertificateBundle{
		PrivateKey: key,
		KeyPEM:     keyPEM,
		CertPEM:    pubKeyPEM, // For SA keys, CertPEM contains the public key
	}, nil
}

// GenerateCACertificate generates a new CA certificate
func GenerateCACertificate(config *CertConfig) (*CertificateBundle, error) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   config.CommonName,
			Organization: config.Organization,
			Country:      config.Country,
			Province:     config.Province,
			Locality:     config.Locality,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(config.ValidityDays) * 24 * time.Hour),
		KeyUsage:              config.KeyUsage,
		ExtKeyUsage:           config.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  config.IsCA,
	}

	if config.IsCA {
		template.MaxPathLen = 0
		template.MaxPathLenZero = true
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return &CertificateBundle{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// GenerateCertificate generates a certificate signed by the given CA
func GenerateCertificate(config *CertConfig, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*CertificateBundle, error) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   config.CommonName,
			Organization: config.Organization,
			Country:      config.Country,
			Province:     config.Province,
			Locality:     config.Locality,
		},
		DNSNames:              config.DNSNames,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(config.ValidityDays) * 24 * time.Hour),
		KeyUsage:              config.KeyUsage,
		ExtKeyUsage:           config.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  config.IsCA,
	}

	// Parse IP addresses
	for _, ipStr := range config.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return &CertificateBundle{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// ParseCertificateFromPEM parses a certificate from PEM data
func ParseCertificateFromPEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// ParsePrivateKeyFromPEM parses an RSA private key from PEM data
func ParsePrivateKeyFromPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}
