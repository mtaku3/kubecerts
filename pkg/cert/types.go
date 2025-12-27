package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Certificate types and configurations
type CertConfig struct {
	CommonName   string
	Organization []string
	Country      []string
	Province     []string
	Locality     []string
	DNSNames     []string
	IPAddresses  []string
	ValidityDays int
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	IsCA         bool
}

type CertificateBundle struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
}

// Default certificate configurations
var (
	CAValidityDays   = 365 * 5 // 5 years
	CertValidityDays = 365     // 1 year
)

// Certificate profiles
func NewKubernetesCAConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "kubernetes-ca",
		ValidityDays: CAValidityDays,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
	}
}

func NewFrontProxyCAConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "front-proxy-ca",
		ValidityDays: CAValidityDays,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
	}
}

func NewEtcdCAConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "etcd-ca",
		ValidityDays: CAValidityDays,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
	}
}

func NewAPIServerConfig(hostName, hostIP string) *CertConfig {
	// Get additional configuration values from nix
	clusterDomain, masterAddress := getKubernetesConfigValues(hostName)
	
	// Build DNS names list
	dnsNames := []string{
		hostName,
		"kubernetes",
		"kubernetes.default",
		"kubernetes.default.svc",
	}
	
	// Add cluster domain based SANs
	if clusterDomain != "" {
		dnsNames = append(dnsNames, "kubernetes.default.svc."+clusterDomain)
	}
	
	// Build IP addresses list
	ipAddresses := []string{hostIP, "10.0.0.1"}
	
	// Add masterAddress - it could be either IP or domain
	if masterAddress != "" {
		if net.ParseIP(masterAddress) != nil {
			// It's an IP address
			ipAddresses = append(ipAddresses, masterAddress)
		} else {
			// It's a domain name
			dnsNames = append(dnsNames, masterAddress)
		}
	}
	
	return &CertConfig{
		CommonName:   "kube-apiserver",
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func NewAPIServerKubeletClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "kube-apiserver-kubelet-client",
		Organization: []string{"system:masters"},
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewAPIServerEtcdClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "kube-apiserver-etcd-client",
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewFrontProxyClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "front-proxy-client",
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewEtcdServerConfig(hostName, hostIP string) *CertConfig {
	// Get additional configuration values from nix
	clusterDomain, masterAddress := getKubernetesConfigValues(hostName)
	
	// Build DNS names list
	dnsNames := []string{
		hostName,
		"localhost",
		"etcd.local",
	}
	
	// Add cluster domain based SANs
	if clusterDomain != "" {
		dnsNames = append(dnsNames, "etcd."+clusterDomain)
	}
	
	// Build IP addresses list
	ipAddresses := []string{hostIP, "127.0.0.1"}
	
	// Add masterAddress - it could be either IP or domain
	if masterAddress != "" {
		if net.ParseIP(masterAddress) != nil {
			// It's an IP address
			ipAddresses = append(ipAddresses, masterAddress)
		} else {
			// It's a domain name
			dnsNames = append(dnsNames, masterAddress)
		}
	}
	
	return &CertConfig{
		CommonName:   "kube-etcd",
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

func NewEtcdPeerConfig(hostName, hostIP string) *CertConfig {
	// Get additional configuration values from nix
	clusterDomain, masterAddress := getKubernetesConfigValues(hostName)
	
	// Build DNS names list
	dnsNames := []string{
		hostName,
		"localhost",
		"etcd.local",
	}
	
	// Add cluster domain based SANs
	if clusterDomain != "" {
		dnsNames = append(dnsNames, "etcd."+clusterDomain)
	}
	
	// Build IP addresses list
	ipAddresses := []string{hostIP, "127.0.0.1"}
	
	// Add masterAddress - it could be either IP or domain
	if masterAddress != "" {
		if net.ParseIP(masterAddress) != nil {
			// It's an IP address
			ipAddresses = append(ipAddresses, masterAddress)
		} else {
			// It's a domain name
			dnsNames = append(dnsNames, masterAddress)
		}
	}

	return &CertConfig{
		CommonName:   "kube-etcd-peer",
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

func NewEtcdHealthcheckClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "kube-etcd-healthcheck-client",
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewFlannelEtcdClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "flannel-etcd-client",
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewKubeletClientConfig(nodeName string) *CertConfig {
	return &CertConfig{
		CommonName:   "system:node:" + nodeName,
		Organization: []string{"system:nodes"},
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// NewKubeletServerConfig creates configuration for kubelet server certificate (CN=hostname)
func NewKubeletServerConfig(hostName, hostIP string) *CertConfig {
	return &CertConfig{
		CommonName:   hostName,
		DNSNames:     []string{hostName},
		IPAddresses:  []string{hostIP},
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// NewControllerManagerServerConfig creates configuration for controller-manager server certificate
// Uses same SANs as apiserver but with CN=kube-controller-manager
func NewControllerManagerServerConfig(hostName, hostIP string) *CertConfig {
	// Get additional configuration values from nix
	clusterDomain, masterAddress := getKubernetesConfigValues(hostName)
	
	// Build DNS names list (same as apiserver)
	dnsNames := []string{
		hostName,
		"kubernetes",
		"kubernetes.default",
		"kubernetes.default.svc",
	}
	
	// Add cluster domain based SANs
	if clusterDomain != "" {
		dnsNames = append(dnsNames, "kubernetes.default.svc."+clusterDomain)
	}
	
	// Build IP addresses list
	ipAddresses := []string{hostIP, "10.0.0.1"}
	
	// Add masterAddress - it could be either IP or domain
	if masterAddress != "" {
		if net.ParseIP(masterAddress) != nil {
			// It's an IP address
			ipAddresses = append(ipAddresses, masterAddress)
		} else {
			// It's a domain name
			dnsNames = append(dnsNames, masterAddress)
		}
	}
	
	return &CertConfig{
		CommonName:   "kube-controller-manager",
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// NewSchedulerServerConfig creates configuration for scheduler server certificate
// Uses same SANs as apiserver but with CN=kube-scheduler
func NewSchedulerServerConfig(hostName, hostIP string) *CertConfig {
	// Get additional configuration values from nix
	clusterDomain, masterAddress := getKubernetesConfigValues(hostName)
	
	// Build DNS names list (same as apiserver)
	dnsNames := []string{
		hostName,
		"kubernetes",
		"kubernetes.default",
		"kubernetes.default.svc",
	}
	
	// Add cluster domain based SANs
	if clusterDomain != "" {
		dnsNames = append(dnsNames, "kubernetes.default.svc."+clusterDomain)
	}
	
	// Build IP addresses list
	ipAddresses := []string{hostIP}
	
	// Add masterAddress - it could be either IP or domain
	if masterAddress != "" {
		if net.ParseIP(masterAddress) != nil {
			// It's an IP address
			ipAddresses = append(ipAddresses, masterAddress)
		} else {
			// It's a domain name
			dnsNames = append(dnsNames, masterAddress)
		}
	}
	
	return &CertConfig{
		CommonName:   "kube-scheduler",
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func NewControllerManagerClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "system:kube-controller-manager",
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewSchedulerClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "system:kube-scheduler",
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewAddonManagerClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "system:kube-addon-manager",
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewFlannelClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "flannel-client",
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewKubeProxyClientConfig(nodeName string) *CertConfig {
	return &CertConfig{
		CommonName:   "system:kube-proxy",
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func NewClusterAdminClientConfig() *CertConfig {
	return &CertConfig{
		CommonName:   "cluster-admin",
		Organization: []string{"system:masters"},
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// getKubernetesConfigValues retrieves cluster configuration from nix
func getKubernetesConfigValues(hostName string) (clusterDomain, masterAddress string) {
	// Get cluster domain
	cmd := exec.Command("nix", "eval", "--raw", fmt.Sprintf(".#nixosConfigurations.%s.config.services.kubernetes.addons.dns.clusterDomain", hostName))
	out, err := cmd.Output()
	if err == nil {
		clusterDomain = strings.TrimSpace(string(out))
	}
	// If not found or error, use default
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}
	
	// Get master address
	cmd = exec.Command("nix", "eval", "--raw", fmt.Sprintf(".#nixosConfigurations.%s.config.services.kubernetes.masterAddress", hostName))
	out, err = cmd.Output()
	if err == nil {
		masterAddress = strings.TrimSpace(string(out))
	}
	
	return clusterDomain, masterAddress
}
