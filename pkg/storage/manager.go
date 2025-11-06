package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mtaku3/kubecerts/pkg/crypto"
	"github.com/mtaku3/kubecerts/pkg/host"
	"github.com/sirupsen/logrus"
)

const (
	DefaultSecretsPath = "./secrets"
	PKISubPath         = "kubernetes/pki"
)

// StorageManager handles certificate storage with agenix encryption
type StorageManager struct {
	basePath string
	crypto   *crypto.AgenixCrypto
}

// NewStorageManager creates a new storage manager
func NewStorageManager(basePath string, cryptoManager *crypto.AgenixCrypto) *StorageManager {
	if basePath == "" {
		basePath = DefaultSecretsPath
	}

	return &StorageManager{
		basePath: basePath,
		crypto:   cryptoManager,
	}
}

// GetHostPath returns the path for a specific host's certificates
func (sm *StorageManager) GetHostPath(host host.Host) string {
	return filepath.Join(sm.basePath, host.System, host.Name, PKISubPath)
}

// GetCAPath returns the path for CA certificates (shared across all hosts)
func (sm *StorageManager) GetCAPath(system string) string {
	return filepath.Join(sm.basePath, system, "ca")
}

// EnsureHostDirectory creates the directory structure for a host
func (sm *StorageManager) EnsureHostDirectory(host host.Host) error {
	hostPath := sm.GetHostPath(host)
	etcdPath := filepath.Join(hostPath, "etcd")

	if err := os.MkdirAll(hostPath, 0755); err != nil {
		return fmt.Errorf("failed to create host directory %s: %w", hostPath, err)
	}

	if err := os.MkdirAll(etcdPath, 0755); err != nil {
		return fmt.Errorf("failed to create etcd directory %s: %w", etcdPath, err)
	}

	logrus.Debugf("Created directory structure for host %s at %s", host.Name, hostPath)
	return nil
}

// SaveCertificate saves a certificate to the host's directory
func (sm *StorageManager) SaveCertificate(host host.Host, filename string, data []byte) error {
	hostPath := sm.GetHostPath(host)
	fullPath := filepath.Join(hostPath, filename+".age")

	// Encrypt the data
	encryptedData, err := sm.crypto.Encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt certificate data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(fullPath, encryptedData, 0644); err != nil {
		return fmt.Errorf("failed to write certificate file %s: %w", fullPath, err)
	}

	logrus.Debugf("Saved encrypted certificate %s for host %s", filename, host.Name)
	return nil
}

// SavePrivateKey saves a private key to the host's directory
func (sm *StorageManager) SavePrivateKey(host host.Host, filename string, data []byte) error {
	hostPath := sm.GetHostPath(host)
	fullPath := filepath.Join(hostPath, filename+".age")

	// Encrypt the data
	encryptedData, err := sm.crypto.Encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key data: %w", err)
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(fullPath, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write private key file %s: %w", fullPath, err)
	}

	logrus.Debugf("Saved encrypted private key %s for host %s", filename, host.Name)
	return nil
}

// LoadCertificate loads and decrypts a certificate
func (sm *StorageManager) LoadCertificate(host host.Host, filename string) ([]byte, error) {
	hostPath := sm.GetHostPath(host)
	fullPath := filepath.Join(hostPath, filename+".age")

	// Read encrypted file
	encryptedData, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %w", fullPath, err)
	}

	// Decrypt the data
	data, err := sm.crypto.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt certificate data: %w", err)
	}

	return data, nil
}

// LoadPrivateKey loads and decrypts a private key
func (sm *StorageManager) LoadPrivateKey(host host.Host, filename string) ([]byte, error) {
	hostPath := sm.GetHostPath(host)
	fullPath := filepath.Join(hostPath, filename+".age")

	// Read encrypted file
	encryptedData, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", fullPath, err)
	}

	// Decrypt the data
	data, err := sm.crypto.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key data: %w", err)
	}

	return data, nil
}

// CertificateExists checks if a certificate file exists
func (sm *StorageManager) CertificateExists(host host.Host, filename string) bool {
	hostPath := sm.GetHostPath(host)
	fullPath := filepath.Join(hostPath, filename+".age")
	_, err := os.Stat(fullPath)
	return err == nil
}

// DistributeCAToHosts copies CA certificates to all hosts for deployment
func (sm *StorageManager) DistributeCAToHosts(hosts []host.Host, caCertFiles map[string][]byte) error {
	for _, h := range hosts {
		if err := sm.EnsureHostDirectory(h); err != nil {
			return fmt.Errorf("failed to ensure directory for host %s: %w", h.Name, err)
		}

		// Save CA certificates to each host
		for filename, data := range caCertFiles {
			if err := sm.SaveCertificate(h, filename, data); err != nil {
				return fmt.Errorf("failed to save CA certificate %s to host %s: %w", filename, h.Name, err)
			}
		}
	}

	logrus.Infof("Distributed CA certificates to %d hosts", len(hosts))
	return nil
}