package sync

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	ageHandler "github.com/mtaku3/kubecerts/pkg/age"
	"github.com/mtaku3/kubecerts/pkg/ca"
	"github.com/mtaku3/kubecerts/pkg/types"
)

type Syncer struct {
	secretsDir string
	ageHandler *ageHandler.Handler
}

func NewSyncer(secretsDir string, handler *ageHandler.Handler) *Syncer {
	return &Syncer{
		secretsDir: secretsDir,
		ageHandler: handler,
	}
}

func (s *Syncer) DeployCertificate(ctx context.Context, host types.Host, caType ca.CAType, cert *x509.Certificate, key *rsa.PrivateKey) error {
	// Convert certificate and key to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	// Get file paths
	certPath, keyPath := s.getCertificatePaths(host, caType)

	// Encrypt and write certificate
	if err := s.writeEncryptedFile(certPath, certPEM); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Encrypt and write key
	if err := s.writeEncryptedFile(keyPath, keyPEM); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return nil
}

func (s *Syncer) writeEncryptedFile(path string, data []byte) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// TODO: Load recipients from configuration
	// For now, we'll need to implement recipient loading
	recipients, err := s.loadRecipients()
	if err != nil {
		return fmt.Errorf("failed to load recipients: %w", err)
	}

	encryptedData, err := s.ageHandler.EncryptData(data, recipients...)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	if err := os.WriteFile(path, encryptedData, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}

	return nil
}

func (s *Syncer) getCertificatePaths(host types.Host, caType ca.CAType) (string, string) {
	basePath := filepath.Join(s.secretsDir, host.System, host.Name, "kubernetes", "pki")
	
	switch caType {
	case ca.CATypeKubernetes:
		return filepath.Join(basePath, "ca.crt.age"), filepath.Join(basePath, "ca.key.age")
	case ca.CATypeETCD:
		return filepath.Join(basePath, "etcd", "ca.crt.age"), filepath.Join(basePath, "etcd", "ca.key.age")
	case ca.CATypeFrontProxy:
		return filepath.Join(basePath, "front-proxy-ca.crt.age"), filepath.Join(basePath, "front-proxy-ca.key.age")
	default:
		panic(fmt.Sprintf("unknown CA type: %s", caType))
	}
}

func (s *Syncer) loadRecipients() ([]age.Recipient, error) {
	// Use the age handler's identities as recipients for self-encryption
	return s.ageHandler.GetRecipients()
}