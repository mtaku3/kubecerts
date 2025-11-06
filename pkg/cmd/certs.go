package cmd

import (
	"fmt"

	"github.com/mtaku3/kubecerts/pkg/cert"
	"github.com/mtaku3/kubecerts/pkg/crypto"
	"github.com/mtaku3/kubecerts/pkg/host"
	"github.com/mtaku3/kubecerts/pkg/storage"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// CertManager handles certificate generation operations
type CertManager struct {
	storage *storage.StorageManager
	crypto  *crypto.AgenixCrypto
	hosts   []host.Host
}

// NewCertManager creates a new certificate manager
func NewCertManager() (*CertManager, error) {
	// Initialize crypto
	crypto, err := crypto.NewAgenixCrypto("")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize crypto: %w", err)
	}

	// Initialize storage
	storage := storage.NewStorageManager("", crypto)

	// Discover hosts
	hosts, err := host.GetHosts()
	if err != nil {
		return nil, fmt.Errorf("failed to discover hosts: %w", err)
	}

	return &CertManager{
		storage: storage,
		crypto:  crypto,
		hosts:   hosts,
	}, nil
}

// NewCertsCommand creates the certs command
func NewCertsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certs",
		Short: "Certificate generation commands",
		Long:  "Phase-based certificate generation for Kubernetes clusters",
	}

	cmd.AddCommand(newCertsAllCommand())
	cmd.AddCommand(newCertsCACommand())
	cmd.AddCommand(newCertsAPIServerCommand())
	cmd.AddCommand(newCertsEtcdCommand())
	cmd.AddCommand(newCertsSACommand())
	cmd.AddCommand(newCertsKubeletCommand())

	return cmd
}

func newCertsAllCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "all",
		Short: "Generate all certificates",
		Long:  "Generate all certificates for the cluster including CAs and service certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm, err := NewCertManager()
			if err != nil {
				return err
			}

			logrus.Info("Generating all certificates...")
			
			if err := cm.GenerateCACertificates(); err != nil {
				return fmt.Errorf("failed to generate CA certificates: %w", err)
			}
			
			if err := cm.GenerateServiceAccountKeys(); err != nil {
				return fmt.Errorf("failed to generate service account keys: %w", err)
			}
			
			if err := cm.GenerateAPIServerCertificates(); err != nil {
				return fmt.Errorf("failed to generate API server certificates: %w", err)
			}
			
			if err := cm.GenerateEtcdCertificates(); err != nil {
				return fmt.Errorf("failed to generate etcd certificates: %w", err)
			}
			
			if err := cm.GenerateKubeletCertificates(); err != nil {
				return fmt.Errorf("failed to generate kubelet certificates: %w", err)
			}

			logrus.Info("All certificates generated successfully")
			return nil
		},
	}
}

func newCertsCACommand() *cobra.Command {
	return &cobra.Command{
		Use:   "ca",
		Short: "Generate CA certificates",
		Long:  "Generate Certificate Authority certificates (kubernetes-ca, front-proxy-ca, etcd-ca)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm, err := NewCertManager()
			if err != nil {
				return err
			}

			logrus.Info("Generating CA certificates...")
			return cm.GenerateCACertificates()
		},
	}
}

func newCertsAPIServerCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "apiserver",
		Short: "Generate API server certificates",
		Long:  "Generate API server certificates for master nodes",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm, err := NewCertManager()
			if err != nil {
				return err
			}

			logrus.Info("Generating API server certificates...")
			return cm.GenerateAPIServerCertificates()
		},
	}
}

func newCertsEtcdCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "etcd",
		Short: "Generate etcd certificates",
		Long:  "Generate etcd certificates for master nodes",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm, err := NewCertManager()
			if err != nil {
				return err
			}

			logrus.Info("Generating etcd certificates...")
			return cm.GenerateEtcdCertificates()
		},
	}
}

func newCertsSACommand() *cobra.Command {
	return &cobra.Command{
		Use:   "sa",
		Short: "Generate service account key pair",
		Long:  "Generate service account signing key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm, err := NewCertManager()
			if err != nil {
				return err
			}

			logrus.Info("Generating service account keys...")
			return cm.GenerateServiceAccountKeys()
		},
	}
}

func newCertsKubeletCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "kubelet",
		Short: "Generate kubelet client certificates",
		Long:  "Generate kubelet client certificates for all nodes",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm, err := NewCertManager()
			if err != nil {
				return err
			}

			logrus.Info("Generating kubelet certificates...")
			return cm.GenerateKubeletCertificates()
		},
	}
}

// GenerateCACertificates generates all CA certificates
func (cm *CertManager) GenerateCACertificates() error {
	caCerts := make(map[string][]byte)
	
	// Get unique systems
	systems := make(map[string]bool)
	for _, h := range cm.hosts {
		systems[h.System] = true
	}

	// Generate CAs for each system
	for system := range systems {
		// Generate Kubernetes CA
		kubeCA, err := cert.GenerateCACertificate(cert.NewKubernetesCAConfig())
		if err != nil {
			return fmt.Errorf("failed to generate kubernetes CA: %w", err)
		}
		caCerts["ca.crt"] = kubeCA.CertPEM

		// Generate Front Proxy CA
		frontProxyCA, err := cert.GenerateCACertificate(cert.NewFrontProxyCAConfig())
		if err != nil {
			return fmt.Errorf("failed to generate front-proxy CA: %w", err)
		}
		caCerts["front-proxy-ca.crt"] = frontProxyCA.CertPEM

		// Generate Etcd CA
		etcdCA, err := cert.GenerateCACertificate(cert.NewEtcdCAConfig())
		if err != nil {
			return fmt.Errorf("failed to generate etcd CA: %w", err)
		}
		caCerts["etcd/ca.crt"] = etcdCA.CertPEM

		// Save CA keys to master nodes only
		for _, h := range cm.hosts {
			if h.System != system {
				continue
			}
			
			if err := cm.storage.EnsureHostDirectory(h); err != nil {
				return fmt.Errorf("failed to ensure directory for host %s: %w", h.Name, err)
			}

			if h.Role == host.Master {
				// Master nodes get CA private keys
				if err := cm.storage.SavePrivateKey(h, "ca.key", kubeCA.KeyPEM); err != nil {
					return fmt.Errorf("failed to save kubernetes CA key: %w", err)
				}
				if err := cm.storage.SavePrivateKey(h, "front-proxy-ca.key", frontProxyCA.KeyPEM); err != nil {
					return fmt.Errorf("failed to save front-proxy CA key: %w", err)
				}
				if err := cm.storage.SavePrivateKey(h, "etcd/ca.key", etcdCA.KeyPEM); err != nil {
					return fmt.Errorf("failed to save etcd CA key: %w", err)
				}
			}
		}
	}

	// Distribute CA certificates to all hosts
	if err := cm.storage.DistributeCAToHosts(cm.hosts, caCerts); err != nil {
		return fmt.Errorf("failed to distribute CA certificates: %w", err)
	}

	logrus.Info("CA certificates generated and distributed successfully")
	return nil
}

// GenerateServiceAccountKeys generates service account signing keys
func (cm *CertManager) GenerateServiceAccountKeys() error {
	saKeys, err := cert.GenerateServiceAccountKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate service account keys: %w", err)
	}

	// Save to master nodes only
	for _, h := range cm.hosts {
		if h.Role == host.Master {
			if err := cm.storage.SavePrivateKey(h, "sa.key", saKeys.KeyPEM); err != nil {
				return fmt.Errorf("failed to save service account private key: %w", err)
			}
			if err := cm.storage.SaveCertificate(h, "sa.pub", saKeys.CertPEM); err != nil {
				return fmt.Errorf("failed to save service account public key: %w", err)
			}
		}
	}

	logrus.Info("Service account keys generated successfully")
	return nil
}

// GenerateAPIServerCertificates generates API server certificates for master nodes
func (cm *CertManager) GenerateAPIServerCertificates() error {
	for _, h := range cm.hosts {
		if h.Role != host.Master {
			continue
		}

		// Load CA certificate and key
		caCertPEM, err := cm.storage.LoadCertificate(h, "ca.crt")
		if err != nil {
			return fmt.Errorf("failed to load CA certificate for host %s: %w", h.Name, err)
		}
		caKeyPEM, err := cm.storage.LoadPrivateKey(h, "ca.key")
		if err != nil {
			return fmt.Errorf("failed to load CA key for host %s: %w", h.Name, err)
		}

		caCert, err := cert.ParseCertificateFromPEM(caCertPEM)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		caKey, err := cert.ParsePrivateKeyFromPEM(caKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to parse CA key: %w", err)
		}

		// Generate API server certificate
		apiServerCert, err := cert.GenerateCertificate(cert.NewAPIServerConfig(h.Name, h.AdvertiseIP), caCert, caKey)
		if err != nil {
			return fmt.Errorf("failed to generate API server certificate: %w", err)
		}

		// Generate API server kubelet client certificate
		kubeletClientCert, err := cert.GenerateCertificate(cert.NewAPIServerKubeletClientConfig(), caCert, caKey)
		if err != nil {
			return fmt.Errorf("failed to generate API server kubelet client certificate: %w", err)
		}

		// Generate API server etcd client certificate
		etcdClientCert, err := cert.GenerateCertificate(cert.NewAPIServerEtcdClientConfig(), caCert, caKey)
		if err != nil {
			return fmt.Errorf("failed to generate API server etcd client certificate: %w", err)
		}

		// Load front-proxy CA certificate and key
		frontProxyCACertPEM, err := cm.storage.LoadCertificate(h, "front-proxy-ca.crt")
		if err != nil {
			return fmt.Errorf("failed to load front-proxy CA certificate for host %s: %w", h.Name, err)
		}
		frontProxyCAKeyPEM, err := cm.storage.LoadPrivateKey(h, "front-proxy-ca.key")
		if err != nil {
			return fmt.Errorf("failed to load front-proxy CA key for host %s: %w", h.Name, err)
		}

		frontProxyCACert, err := cert.ParseCertificateFromPEM(frontProxyCACertPEM)
		if err != nil {
			return fmt.Errorf("failed to parse front-proxy CA certificate: %w", err)
		}
		frontProxyCAKey, err := cert.ParsePrivateKeyFromPEM(frontProxyCAKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to parse front-proxy CA key: %w", err)
		}

		// Generate front-proxy client certificate
		frontProxyClientCert, err := cert.GenerateCertificate(cert.NewFrontProxyClientConfig(), frontProxyCACert, frontProxyCAKey)
		if err != nil {
			return fmt.Errorf("failed to generate front-proxy client certificate: %w", err)
		}

		// Save certificates
		if err := cm.storage.SaveCertificate(h, "apiserver.crt", apiServerCert.CertPEM); err != nil {
			return fmt.Errorf("failed to save API server certificate: %w", err)
		}
		if err := cm.storage.SavePrivateKey(h, "apiserver.key", apiServerCert.KeyPEM); err != nil {
			return fmt.Errorf("failed to save API server key: %w", err)
		}
		if err := cm.storage.SaveCertificate(h, "apiserver-kubelet-client.crt", kubeletClientCert.CertPEM); err != nil {
			return fmt.Errorf("failed to save API server kubelet client certificate: %w", err)
		}
		if err := cm.storage.SavePrivateKey(h, "apiserver-kubelet-client.key", kubeletClientCert.KeyPEM); err != nil {
			return fmt.Errorf("failed to save API server kubelet client key: %w", err)
		}
		if err := cm.storage.SaveCertificate(h, "apiserver-etcd-client.crt", etcdClientCert.CertPEM); err != nil {
			return fmt.Errorf("failed to save API server etcd client certificate: %w", err)
		}
		if err := cm.storage.SavePrivateKey(h, "apiserver-etcd-client.key", etcdClientCert.KeyPEM); err != nil {
			return fmt.Errorf("failed to save API server etcd client key: %w", err)
		}
		if err := cm.storage.SaveCertificate(h, "front-proxy-client.crt", frontProxyClientCert.CertPEM); err != nil {
			return fmt.Errorf("failed to save front-proxy client certificate: %w", err)
		}
		if err := cm.storage.SavePrivateKey(h, "front-proxy-client.key", frontProxyClientCert.KeyPEM); err != nil {
			return fmt.Errorf("failed to save front-proxy client key: %w", err)
		}

		logrus.Infof("Generated API server certificates for host %s", h.Name)
	}

	return nil
}

// GenerateEtcdCertificates generates etcd certificates for master nodes
func (cm *CertManager) GenerateEtcdCertificates() error {
	for _, h := range cm.hosts {
		if h.Role != host.Master {
			continue
		}

		// Load etcd CA certificate and key
		etcdCACertPEM, err := cm.storage.LoadCertificate(h, "etcd/ca.crt")
		if err != nil {
			return fmt.Errorf("failed to load etcd CA certificate for host %s: %w", h.Name, err)
		}
		etcdCAKeyPEM, err := cm.storage.LoadPrivateKey(h, "etcd/ca.key")
		if err != nil {
			return fmt.Errorf("failed to load etcd CA key for host %s: %w", h.Name, err)
		}

		etcdCACert, err := cert.ParseCertificateFromPEM(etcdCACertPEM)
		if err != nil {
			return fmt.Errorf("failed to parse etcd CA certificate: %w", err)
		}
		etcdCAKey, err := cert.ParsePrivateKeyFromPEM(etcdCAKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to parse etcd CA key: %w", err)
		}

		// Generate etcd server certificate
		etcdServerCert, err := cert.GenerateCertificate(cert.NewEtcdServerConfig(h.Name, h.AdvertiseIP), etcdCACert, etcdCAKey)
		if err != nil {
			return fmt.Errorf("failed to generate etcd server certificate: %w", err)
		}

		// Generate etcd peer certificate
		etcdPeerCert, err := cert.GenerateCertificate(cert.NewEtcdPeerConfig(h.Name, h.AdvertiseIP), etcdCACert, etcdCAKey)
		if err != nil {
			return fmt.Errorf("failed to generate etcd peer certificate: %w", err)
		}

		// Generate etcd healthcheck client certificate
		etcdHealthcheckCert, err := cert.GenerateCertificate(cert.NewEtcdHealthcheckClientConfig(), etcdCACert, etcdCAKey)
		if err != nil {
			return fmt.Errorf("failed to generate etcd healthcheck certificate: %w", err)
		}

		// Save certificates
		if err := cm.storage.SaveCertificate(h, "etcd/server.crt", etcdServerCert.CertPEM); err != nil {
			return fmt.Errorf("failed to save etcd server certificate: %w", err)
		}
		if err := cm.storage.SavePrivateKey(h, "etcd/server.key", etcdServerCert.KeyPEM); err != nil {
			return fmt.Errorf("failed to save etcd server key: %w", err)
		}
		if err := cm.storage.SaveCertificate(h, "etcd/peer.crt", etcdPeerCert.CertPEM); err != nil {
			return fmt.Errorf("failed to save etcd peer certificate: %w", err)
		}
		if err := cm.storage.SavePrivateKey(h, "etcd/peer.key", etcdPeerCert.KeyPEM); err != nil {
			return fmt.Errorf("failed to save etcd peer key: %w", err)
		}
		if err := cm.storage.SaveCertificate(h, "etcd/healthcheck-client.crt", etcdHealthcheckCert.CertPEM); err != nil {
			return fmt.Errorf("failed to save etcd healthcheck certificate: %w", err)
		}
		if err := cm.storage.SavePrivateKey(h, "etcd/healthcheck-client.key", etcdHealthcheckCert.KeyPEM); err != nil {
			return fmt.Errorf("failed to save etcd healthcheck key: %w", err)
		}

		logrus.Infof("Generated etcd certificates for host %s", h.Name)
	}

	return nil
}

// GenerateKubeletCertificates generates kubelet client certificates for all nodes
func (cm *CertManager) GenerateKubeletCertificates() error {
	for _, h := range cm.hosts {
		// Load CA certificate and key from any master node
		var caCertPEM, caKeyPEM []byte
		var err error

		// Find a master node to get CA from
		for _, master := range cm.hosts {
			if master.Role == host.Master && master.System == h.System {
				caCertPEM, err = cm.storage.LoadCertificate(master, "ca.crt")
				if err != nil {
					continue
				}
				caKeyPEM, err = cm.storage.LoadPrivateKey(master, "ca.key")
				if err != nil {
					continue
				}
				break
			}
		}

		if caCertPEM == nil {
			return fmt.Errorf("failed to find CA certificate for system %s", h.System)
		}

		caCert, err := cert.ParseCertificateFromPEM(caCertPEM)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		caKey, err := cert.ParsePrivateKeyFromPEM(caKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to parse CA key: %w", err)
		}

		// Generate kubelet client certificate
		kubeletCert, err := cert.GenerateCertificate(cert.NewKubeletClientConfig(h.Name), caCert, caKey)
		if err != nil {
			return fmt.Errorf("failed to generate kubelet certificate for %s: %w", h.Name, err)
		}

		// Save certificate
		if err := cm.storage.SaveCertificate(h, "kubelet-client.crt", kubeletCert.CertPEM); err != nil {
			return fmt.Errorf("failed to save kubelet certificate: %w", err)
		}
		if err := cm.storage.SavePrivateKey(h, "kubelet-client.key", kubeletCert.KeyPEM); err != nil {
			return fmt.Errorf("failed to save kubelet key: %w", err)
		}

		logrus.Infof("Generated kubelet certificate for host %s", h.Name)
	}

	return nil
}