package cert

import (
	"crypto/rsa"
	"crypto/x509"
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
	return &CertConfig{
		CommonName:   "kube-apiserver",
		DNSNames:     []string{hostName},
		IPAddresses:  []string{hostIP},
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
	return &CertConfig{
		CommonName:   "kube-etcd",
		DNSNames:     []string{hostName, "localhost"},
		IPAddresses:  []string{hostIP, "127.0.0.1"},
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

func NewEtcdPeerConfig(hostName, hostIP string) *CertConfig {
	return &CertConfig{
		CommonName:   "kube-etcd-peer",
		DNSNames:     []string{hostName, "localhost"},
		IPAddresses:  []string{hostIP, "127.0.0.1"},
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

func NewKubeletClientConfig(nodeName string) *CertConfig {
	return &CertConfig{
		CommonName:   "system:node:" + nodeName,
		Organization: []string{"system:nodes"},
		ValidityDays: CertValidityDays,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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
