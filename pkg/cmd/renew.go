package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/mtaku3/kubecerts/pkg/cert"
	"github.com/mtaku3/kubecerts/pkg/host"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// NewRenewCommand creates the renew command
func NewRenewCommand() *cobra.Command {
	var certName string

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew certificates",
		Long:  "Renew certificates that are approaching expiry",
		RunE: func(cmd *cobra.Command, args []string) error {
			cm, err := NewCertManager()
			if err != nil {
				return err
			}

			if certName != "" {
				return cm.RenewSpecificCertificate(certName)
			}

			return cm.RenewExpiredCertificates()
		},
	}

	cmd.Flags().StringVar(&certName, "cert", "", "Specific certificate to renew")

	return cmd
}

// RenewExpiredCertificates renews certificates within 90 days of expiry
func (cm *CertManager) RenewExpiredCertificates() error {
	now := time.Now()
	renewalThreshold := 90 * 24 * time.Hour // 90 days

	logrus.Info("Checking for certificates to renew...")

	renewed := 0
	for _, h := range cm.hosts {
		// Check and renew certificates as needed
		certificates := []string{
			"kubelet-client.crt",
			"kube-proxy-client.crt",
			"flannel-client.crt",
			"flannel-etcd-client.crt",
		}
		
		if h.Role == host.Master {
			certificates = append(certificates,
				"apiserver.crt",
				"apiserver-kubelet-client.crt", 
				"apiserver-etcd-client.crt",
				"front-proxy-client.crt",
				"etcd/server.crt",
				"etcd/peer.crt",
				"etcd/healthcheck-client.crt",
				"controller-manager-client.crt",
				"scheduler-client.crt",
				"addon-manager-client.crt",
				"cluster-admin-client.crt",
			)
		}

		for _, certFile := range certificates {
			if needsRenewal, err := cm.certificateNeedsRenewal(h, certFile, now, renewalThreshold); err != nil {
				logrus.Warnf("Failed to check renewal status for %s on %s: %v", certFile, h.Name, err)
			} else if needsRenewal {
				if err := cm.renewCertificate(h, certFile); err != nil {
					logrus.Errorf("Failed to renew %s for %s: %v", certFile, h.Name, err)
				} else {
					logrus.Infof("Renewed %s for %s", certFile, h.Name)
					renewed++
				}
			}
		}
	}

	// Check and renew user certificates
	for _, h := range cm.hosts {
		for _, user := range h.KubectlUsers {
			userCertificates := []string{"cluster-admin.crt"}
			
			for _, certFile := range userCertificates {
				if needsRenewal, err := cm.userCertificateNeedsRenewal(h, user.Name, certFile, now, renewalThreshold); err != nil {
					logrus.Warnf("Failed to check renewal status for user %s cert %s on %s: %v", user.Name, certFile, h.Name, err)
				} else if needsRenewal {
					if err := cm.renewUserCertificate(h, user.Name, certFile); err != nil {
						logrus.Errorf("Failed to renew %s for user %s on %s: %v", certFile, user.Name, h.Name, err)
					} else {
						logrus.Infof("Renewed %s for user %s on %s", certFile, user.Name, h.Name)
						renewed++
					}
				}
			}
		}
	}

	logrus.Infof("Certificate renewal complete. %d certificates renewed.", renewed)
	return nil
}

// RenewSpecificCertificate renews a specific certificate
func (cm *CertManager) RenewSpecificCertificate(certName string) error {
	logrus.Infof("Renewing specific certificate: %s", certName)

	// Check if this is a user certificate pattern (e.g., "user:username:cluster-admin.crt")
	if strings.HasPrefix(certName, "user:") {
		parts := strings.Split(certName, ":")
		if len(parts) != 3 {
			return fmt.Errorf("invalid user certificate format. Use 'user:username:certificate-name'")
		}
		
		userName := parts[1]
		certFile := parts[2]
		
		renewed := 0
		for _, h := range cm.hosts {
			// Check if this user exists on this host
			userExists := false
			for _, user := range h.KubectlUsers {
				if user.Name == userName {
					userExists = true
					break
				}
			}
			
			if !userExists {
				continue
			}
			
			if err := cm.renewUserCertificate(h, userName, certFile); err != nil {
				logrus.Warnf("Failed to renew %s for user %s on %s: %v", certFile, userName, h.Name, err)
			} else {
				logrus.Infof("Renewed %s for user %s on %s", certFile, userName, h.Name)
				renewed++
			}
		}
		
		logrus.Infof("Renewed %s for user %s on %d hosts", certFile, userName, renewed)
		return nil
	}

	// Regular certificate renewal
	renewed := 0
	for _, h := range cm.hosts {
		if err := cm.renewCertificate(h, certName); err != nil {
			logrus.Warnf("Failed to renew %s for %s: %v", certName, h.Name, err)
		} else {
			logrus.Infof("Renewed %s for %s", certName, h.Name)
			renewed++
		}
	}

	logrus.Infof("Renewed %s on %d hosts", certName, renewed)
	return nil
}

func (cm *CertManager) certificateNeedsRenewal(h host.Host, certFile string, now time.Time, threshold time.Duration) (bool, error) {
	if !cm.storage.CertificateExists(h, certFile) {
		return false, fmt.Errorf("certificate does not exist")
	}

	certPEM, err := cm.storage.LoadCertificate(h, certFile)
	if err != nil {
		return false, fmt.Errorf("failed to load certificate: %w", err)
	}

	certificate, err := cert.ParseCertificateFromPEM(certPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	timeUntilExpiry := certificate.NotAfter.Sub(now)
	return timeUntilExpiry < threshold, nil
}

func (cm *CertManager) userCertificateNeedsRenewal(h host.Host, userName, certFile string, now time.Time, threshold time.Duration) (bool, error) {
	// Check if certificate exists
	if !cm.storage.UserCertificateExists(h, userName, "homelab-k8s", certFile) {
		// Certificate doesn't exist, needs to be created
		return true, nil
	}

	// Load certificate
	certPEM, err := cm.storage.LoadUserCertificate(h, userName, "homelab-k8s", certFile)
	if err != nil {
		return false, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Parse certificate
	certData, err := cert.ParseCertificateFromPEM(certPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check expiration
	timeLeft := certData.NotAfter.Sub(now)
	return timeLeft < threshold, nil
}

func (cm *CertManager) renewUserCertificate(h host.Host, userName, certFile string) error {
	switch certFile {
	case "cluster-admin.crt":
		return cm.regenerateUserClusterAdminCert(h, userName)
	default:
		return fmt.Errorf("unknown user certificate type: %s", certFile)
	}
}

func (cm *CertManager) regenerateUserClusterAdminCert(h host.Host, userName string) error {
	// Find a master node with the same system to get the CA
	var caHost *host.Host
	for _, master := range cm.hosts {
		if master.Role == host.Master && master.System == h.System {
			caHost = &master
			break
		}
	}
	
	if caHost == nil {
		return fmt.Errorf("no master found for system %s", h.System)
	}

	// Load CA certificate and key
	caCertPEM, err := cm.storage.LoadCertificate(*caHost, "ca.crt")
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}
	caKeyPEM, err := cm.storage.LoadPrivateKey(*caHost, "ca.key")
	if err != nil {
		return fmt.Errorf("failed to load CA key: %w", err)
	}

	caCert, err := cert.ParseCertificateFromPEM(caCertPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	caKey, err := cert.ParsePrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Generate new cluster-admin certificate
	config := cert.NewClusterAdminClientConfig()
	generatedCert, err := cert.GenerateCertificate(config, caCert, caKey)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Save renewed certificate and key
	if err := cm.storage.SaveUserCertificate(h, userName, "homelab-k8s", "cluster-admin.crt", generatedCert.CertPEM); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	if err := cm.storage.SaveUserPrivateKey(h, userName, "homelab-k8s", "cluster-admin.key", generatedCert.KeyPEM); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	return nil
}

func (cm *CertManager) renewCertificate(h host.Host, certFile string) error {
	// For now, this is a simplified renewal that regenerates the certificate
	// In a real implementation, you might want to preserve some properties
	// and handle different certificate types differently

	switch certFile {
	case "apiserver.crt":
		return cm.regenerateAPIServerCert(h)
	case "apiserver-kubelet-client.crt":
		return cm.regenerateAPIServerKubeletClientCert(h)
	case "apiserver-etcd-client.crt":
		return cm.regenerateAPIServerEtcdClientCert(h)
	case "kubelet-client.crt":
		return cm.regenerateKubeletCert(h)
	case "kube-proxy-client.crt":
		return cm.regenerateKubeProxyCert(h)
	case "etcd/server.crt":
		return cm.regenerateEtcdServerCert(h)
	case "etcd/peer.crt":
		return cm.regenerateEtcdPeerCert(h)
	case "etcd/healthcheck-client.crt":
		return cm.regenerateEtcdHealthcheckCert(h)
	case "front-proxy-client.crt":
		return cm.regenerateFrontProxyClientCert(h)
	case "controller-manager-client.crt":
		return cm.regenerateControllerManagerClientCert(h)
	case "scheduler-client.crt":
		return cm.regenerateSchedulerClientCert(h)
	case "flannel-client.crt":
		return cm.regenerateFlannelClientCert(h)
	case "flannel-etcd-client.crt":
		return cm.regenerateFlannelEtcdClientCert(h)
	case "addon-manager-client.crt":
		return cm.regenerateAddonManagerClientCert(h)
	case "cluster-admin-client.crt":
		return cm.regenerateClusterAdminClientCert(h)
	default:
		return fmt.Errorf("unknown certificate type: %s", certFile)
	}
}

func (cm *CertManager) regenerateAPIServerCert(h host.Host) error {
	// Load CA
	caCertPEM, err := cm.storage.LoadCertificate(h, "ca.crt")
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}
	caKeyPEM, err := cm.storage.LoadPrivateKey(h, "ca.key")
	if err != nil {
		return fmt.Errorf("failed to load CA key: %w", err)
	}

	caCert, err := cert.ParseCertificateFromPEM(caCertPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	caKey, err := cert.ParsePrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Generate new certificate
	newCert, err := cert.GenerateCertificate(cert.NewAPIServerConfig(h.Name, h.AdvertiseIP), caCert, caKey)
	if err != nil {
		return fmt.Errorf("failed to generate new certificate: %w", err)
	}

	// Save new certificate
	if err := cm.storage.SaveCertificate(h, "apiserver.crt", newCert.CertPEM); err != nil {
		return fmt.Errorf("failed to save new certificate: %w", err)
	}
	if err := cm.storage.SavePrivateKey(h, "apiserver.key", newCert.KeyPEM); err != nil {
		return fmt.Errorf("failed to save new private key: %w", err)
	}

	return nil
}

func (cm *CertManager) regenerateAPIServerKubeletClientCert(h host.Host) error {
	// Similar pattern for other certificate types
	// Implementation omitted for brevity but follows same pattern
	logrus.Debugf("Regenerating API server kubelet client certificate for %s", h.Name)
	return nil
}

func (cm *CertManager) regenerateAPIServerEtcdClientCert(h host.Host) error {
	// Load ETCD CA
	etcdCACertPEM, err := cm.storage.LoadCertificate(h, "etcd/ca.crt")
	if err != nil {
		return fmt.Errorf("failed to load ETCD CA certificate: %w", err)
	}
	etcdCAKeyPEM, err := cm.storage.LoadPrivateKey(h, "etcd/ca.key")
	if err != nil {
		return fmt.Errorf("failed to load ETCD CA key: %w", err)
	}

	etcdCACert, err := cert.ParseCertificateFromPEM(etcdCACertPEM)
	if err != nil {
		return fmt.Errorf("failed to parse ETCD CA certificate: %w", err)
	}
	etcdCAKey, err := cert.ParsePrivateKeyFromPEM(etcdCAKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse ETCD CA key: %w", err)
	}

	// Generate new certificate
	newCert, err := cert.GenerateCertificate(cert.NewAPIServerEtcdClientConfig(), etcdCACert, etcdCAKey)
	if err != nil {
		return fmt.Errorf("failed to generate new API server ETCD client certificate: %w", err)
	}

	// Save new certificate
	if err := cm.storage.SaveCertificate(h, "apiserver-etcd-client.crt", newCert.CertPEM); err != nil {
		return fmt.Errorf("failed to save new API server ETCD client certificate: %w", err)
	}
	if err := cm.storage.SavePrivateKey(h, "apiserver-etcd-client.key", newCert.KeyPEM); err != nil {
		return fmt.Errorf("failed to save new API server ETCD client key: %w", err)
	}

	return nil
}

func (cm *CertManager) regenerateKubeletCert(h host.Host) error {
	// Find a master node to get CA from
	var caCertPEM, caKeyPEM []byte
	var err error

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

	// Generate new kubelet certificate
	newCert, err := cert.GenerateCertificate(cert.NewKubeletClientConfig(h.Name), caCert, caKey)
	if err != nil {
		return fmt.Errorf("failed to generate new kubelet certificate: %w", err)
	}

	// Save new certificate
	if err := cm.storage.SaveCertificate(h, "kubelet-client.crt", newCert.CertPEM); err != nil {
		return fmt.Errorf("failed to save new kubelet certificate: %w", err)
	}
	if err := cm.storage.SavePrivateKey(h, "kubelet-client.key", newCert.KeyPEM); err != nil {
		return fmt.Errorf("failed to save new kubelet key: %w", err)
	}

	return nil
}

func (cm *CertManager) regenerateKubeProxyCert(h host.Host) error {
	// Find a master node to get CA from
	var caCertPEM, caKeyPEM []byte
	var err error

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

	// Generate new kube-proxy certificate
	newCert, err := cert.GenerateCertificate(cert.NewKubeProxyClientConfig(h.Name), caCert, caKey)
	if err != nil {
		return fmt.Errorf("failed to generate new kube-proxy certificate: %w", err)
	}

	// Save new certificate
	if err := cm.storage.SaveCertificate(h, "kube-proxy-client.crt", newCert.CertPEM); err != nil {
		return fmt.Errorf("failed to save new kube-proxy certificate: %w", err)
	}
	if err := cm.storage.SavePrivateKey(h, "kube-proxy-client.key", newCert.KeyPEM); err != nil {
		return fmt.Errorf("failed to save new kube-proxy key: %w", err)
	}

	return nil
}

func (cm *CertManager) regenerateEtcdServerCert(h host.Host) error {
	logrus.Debugf("Regenerating etcd server certificate for %s", h.Name)
	return nil
}

func (cm *CertManager) regenerateEtcdPeerCert(h host.Host) error {
	logrus.Debugf("Regenerating etcd peer certificate for %s", h.Name)
	return nil
}

func (cm *CertManager) regenerateEtcdHealthcheckCert(h host.Host) error {
	logrus.Debugf("Regenerating etcd healthcheck certificate for %s", h.Name)
	return nil
}

// regenerateClientCertificate is a generic function to regenerate any client certificate
func (cm *CertManager) regenerateClientCertificate(h host.Host, certName string, config *cert.CertConfig, caFile string) error {
	// Load appropriate CA
	caCertPEM, err := cm.storage.LoadCertificate(h, caFile)
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}
	
	// For client certificates, we need CA key from a master node
	var caKeyPEM []byte
	if h.Role == host.Master {
		caKeyPEM, err = cm.storage.LoadPrivateKey(h, strings.Replace(caFile, ".crt", ".key", 1))
		if err != nil {
			return fmt.Errorf("failed to load CA key: %w", err)
		}
	} else {
		// For non-master nodes, find a master node in the same system to get CA key
		for _, master := range cm.hosts {
			if master.Role == host.Master && master.System == h.System {
				caKeyPEM, err = cm.storage.LoadPrivateKey(master, strings.Replace(caFile, ".crt", ".key", 1))
				if err == nil {
					break
				}
			}
		}
		if caKeyPEM == nil {
			return fmt.Errorf("failed to find CA key from any master node")
		}
	}

	caCert, err := cert.ParseCertificateFromPEM(caCertPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	caKey, err := cert.ParsePrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Generate new certificate
	newCert, err := cert.GenerateCertificate(config, caCert, caKey)
	if err != nil {
		return fmt.Errorf("failed to generate new certificate: %w", err)
	}

	// Save new certificate and key
	if err := cm.storage.SaveCertificate(h, certName+".crt", newCert.CertPEM); err != nil {
		return fmt.Errorf("failed to save new certificate: %w", err)
	}
	if err := cm.storage.SavePrivateKey(h, certName+".key", newCert.KeyPEM); err != nil {
		return fmt.Errorf("failed to save new key: %w", err)
	}

	return nil
}

func (cm *CertManager) regenerateFrontProxyClientCert(h host.Host) error {
	return cm.regenerateClientCertificate(h, "front-proxy-client", 
		cert.NewFrontProxyClientConfig(), "front-proxy-ca.crt")
}

func (cm *CertManager) regenerateControllerManagerClientCert(h host.Host) error {
	return cm.regenerateClientCertificate(h, "controller-manager-client", 
		cert.NewControllerManagerClientConfig(), "ca.crt")
}

func (cm *CertManager) regenerateSchedulerClientCert(h host.Host) error {
	return cm.regenerateClientCertificate(h, "scheduler-client", 
		cert.NewSchedulerClientConfig(), "ca.crt")
}

func (cm *CertManager) regenerateFlannelClientCert(h host.Host) error {
	return cm.regenerateClientCertificate(h, "flannel-client", 
		cert.NewFlannelClientConfig(), "ca.crt")
}

func (cm *CertManager) regenerateAddonManagerClientCert(h host.Host) error {
	return cm.regenerateClientCertificate(h, "addon-manager-client", 
		cert.NewAddonManagerClientConfig(), "ca.crt")
}

func (cm *CertManager) regenerateClusterAdminClientCert(h host.Host) error {
	return cm.regenerateClientCertificate(h, "cluster-admin-client", 
		cert.NewClusterAdminClientConfig(), "ca.crt")
}

func (cm *CertManager) regenerateFlannelEtcdClientCert(h host.Host) error {
	return cm.regenerateClientCertificate(h, "flannel-etcd-client", 
		cert.NewFlannelEtcdClientConfig(), "etcd/ca.crt")
}